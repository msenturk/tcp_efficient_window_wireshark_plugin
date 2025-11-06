-- tcp_efficient_window.lua
-- Advanced TCP Effective Window post-dissector
-- Features:
--  * Conversation-aware window scaling (learns scale from SYN/SYN-ACK only)
--  * Heuristic Cwnd estimation (optional)
--  * EffectiveWindow = max(0, min(Rwnd, Cwnd_est) - BytesInFlight)
--  * Optional CSV export via TAP (configurable + throttled)
--  * Safe field handling and per-packet caching
--  * State cleared on capture reload
--  * Production-ready with proper error handling

local proto_eff = Proto("tcp_efficient_window", "TCP Effective Window (enhanced)")

-- Public Fields (visible in UI)
local f_effwin_value   = ProtoField.uint32("tcp.effwin.value", "Effective Window (bytes)")
local f_effwin_type    = ProtoField.string("tcp.effwin.type", "Calculation Type")
local f_effwin_details = ProtoField.string("tcp.effwin.details", "Details")
local f_cwnd_est       = ProtoField.uint32("tcp.effwin.cwnd_est", "Estimated Cwnd (bytes)")

-- Private Fields (for internal TAP communication, not displayed)
local f_private_rwnd   = ProtoField.uint32("tcp.effwin.private.rwnd", "Private Rwnd")
local f_private_bif    = ProtoField.uint32("tcp.effwin.private.bif", "Private BytesInFlight")
local f_private_key    = ProtoField.string("tcp.effwin.private.key", "Private Flow Key")

proto_eff.fields = { f_effwin_value, f_effwin_type, f_effwin_details, f_cwnd_est, 
                     f_private_rwnd, f_private_bif, f_private_key }

-- Preferences
proto_eff.prefs.show_in_info      = Pref.bool("Append to Info column", true, "Append [EffWin] to Info column")
proto_eff.prefs.enable_cwnd_est   = Pref.bool("Enable heuristic Cwnd estimation", true, "Estimate congestion window from bytes_in_flight")
proto_eff.prefs.enable_csv        = Pref.bool("Enable CSV export", false, "Write per-packet EffWin to CSV")
proto_eff.prefs.csv_path          = Pref.string("CSV path", "/tmp/tcp_effwin.csv", "CSV output file path")
proto_eff.prefs.csv_every_n       = Pref.uint32("CSV write every N packets", 1, "Throttle CSV writes (1 = every packet)")

-- Internal state (per-capture)
local conv_scale = {}
local flow_cwnd  = {}
local csv_file   = nil
local csv_pkt_counter = 0

-- Detect Lua version properly
local lua_version = tonumber(_VERSION:match("(%d+%.%d+)"))
local has_bitshift = (lua_version and lua_version >= 5.3)

-- Safe field factory
local function safe_field(name)
    local ok, f = pcall(function() return Field.new(name) end)
    return ok and f or nil
end

-- Field accessors (cached, initialized after TCP dissector loads)
local f_bytes_in_flight = nil
local f_win_raw         = nil
local f_win_scale       = nil
local f_tcp_flags       = nil
local f_tcp_stream      = nil
local f_tcp_flags_syn   = nil

local function init_fields()
    if not f_bytes_in_flight then
        f_bytes_in_flight = safe_field("tcp.analysis.bytes_in_flight")
        f_win_raw         = safe_field("tcp.window_size_value")
        f_win_scale       = safe_field("tcp.window_size_scalefactor")
        f_tcp_flags       = safe_field("tcp.flags")
        f_tcp_stream      = safe_field("tcp.stream")
        f_tcp_flags_syn   = safe_field("tcp.flags.syn")
    end
end

-- Utility: safe convert FieldInfo to number
local function field_to_number(fi)
    if not fi then return nil end
    local s = tostring(fi)
    if s == "" then return nil end
    return tonumber(s)
end

-- Flow key (stream-aware, unidirectional): "stream:IP:port>IP:port"
local function flow_key(pinfo)
    local stream_fi = f_tcp_stream and f_tcp_stream()
    local stream = field_to_number(stream_fi) or "unknown"
    return tostring(stream) .. ":" .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) 
           .. ">" .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port)
end

-- Check if packet is SYN or SYN-ACK (cached field)
local function is_syn_packet()
    if not f_tcp_flags_syn then return false end
    local syn_fi = f_tcp_flags_syn()
    return syn_fi and field_to_number(syn_fi) == 1
end

-- Learn/retrieve window scale for a direction (only from SYN packets)
local function get_conv_scale(pinfo, win_scale_fi, is_syn)
    local key = flow_key(pinfo)
    local scale = conv_scale[key]
    if scale ~= nil then return scale end
    
    -- Only learn scale from SYN packets
    if not is_syn then return 0 end
    
    local sf = win_scale_fi or (f_win_scale and f_win_scale())
    scale = field_to_number(sf) or 0
    if scale < 0 then scale = 0 end
    if scale > 14 then scale = 14 end  -- RFC 7323: max scale is 14
    conv_scale[key] = scale
    return scale
end

-- Compute scaled Rwnd for current packet
local function get_scaled_rwnd_from(fi_win_raw, fi_win_scale, pinfo, is_syn)
    local win = field_to_number(fi_win_raw)
    if not win then return nil end
    local scale = get_conv_scale(pinfo, fi_win_scale, is_syn)
    
    -- Early return for no scaling
    if scale == 0 then return win end
    
    local scaled = win
    
    -- Use bit shift if available (Lua 5.3+) - properly detected
    if has_bitshift then
        local ok, result = pcall(function()
            return win << scale
        end)
        if ok then
            scaled = result
            if scaled > 0xFFFFFFFF then scaled = 0xFFFFFFFF end
        else
            -- Fallback to multiplication if bit shift fails
            for i = 1, scale do
                scaled = scaled * 2
                if scaled > 0xFFFFFFFF then 
                    scaled = 0xFFFFFFFF 
                    break
                end
            end
        end
    else
        -- Fallback for Lua 5.1/5.2
        for i = 1, scale do
            scaled = scaled * 2
            if scaled > 0xFFFFFFFF then 
                scaled = 0xFFFFFFFF 
                break
            end
        end
    end
    
    return scaled
end

-- Heuristic Cwnd estimator with improved algorithm
local function estimate_cwnd(pinfo, bytes_in_flight)
    if not proto_eff.prefs.enable_cwnd_est then return nil end
    local key = flow_key(pinfo)
    local prev = flow_cwnd[key]
    
    -- Initialize on first packet
    if not prev then
        prev = bytes_in_flight or 0
        flow_cwnd[key] = prev
        return prev
    end
    
    if not bytes_in_flight then return prev end
    
    local new_cwnd
    if bytes_in_flight > prev then
        -- Cwnd is growing (slow start or congestion avoidance)
        new_cwnd = bytes_in_flight
    else
        -- Use EMA with alpha=0.25 for faster response
        new_cwnd = (prev * 0.75) + (bytes_in_flight * 0.25)
    end
    
    flow_cwnd[key] = new_cwnd
    return new_cwnd
end

-- Dissector function
function proto_eff.dissector(buffer, pinfo, tree)
    -- Initialize fields on first use
    init_fields()
    
    -- Skip if not TCP
    local protocol = tostring(pinfo.cols.protocol)
    if protocol ~= "TCP" then return end
    
    -- Skip revisits unless CSV is enabled (TAP needs fields on all passes)
    if pinfo.visited and not proto_eff.prefs.enable_csv then return end

    -- Per-packet FieldInfo caching
    local win_raw_fi = f_win_raw and f_win_raw()
    local win_scale_fi = f_win_scale and f_win_scale()
    local bif_fi = f_bytes_in_flight and f_bytes_in_flight()
    local is_syn = is_syn_packet()

    local rwnd = get_scaled_rwnd_from(win_raw_fi, win_scale_fi, pinfo, is_syn)
    local bytes_in_flight = field_to_number(bif_fi)
    local cwnd_est = estimate_cwnd(pinfo, bytes_in_flight) or (rwnd or 0)
    local key = flow_key(pinfo)

    -- Compute Effective Window
    local eff_val, calc_type, details
    if rwnd and bytes_in_flight then
        eff_val = math.max(0, math.min(rwnd, cwnd_est) - bytes_in_flight)
        calc_type = "min(Rwnd,Cwnd_est)-BytesInFlight"
        details = string.format("Rwnd=%d, Cwnd_est=%.0f, BytesInFlight=%d", rwnd, cwnd_est, bytes_in_flight)
    elseif rwnd then
        eff_val, calc_type, details = rwnd, "Rwnd Only", "BytesInFlight unavailable"
    elseif bytes_in_flight then
        eff_val, calc_type, details = 0, "BytesInFlight Only", 
                                      string.format("BytesInFlight=%d (Rwnd unknown)", bytes_in_flight)
    else
        return 0  -- No useful data available
    end

    -- Safe buffer access for post-dissector (always use empty range)
    local buf_range = buffer(0, 0)
    
    local subtree = tree:add(proto_eff, buf_range, "TCP Effective Window (enhanced)")
    subtree:add(f_effwin_value, buf_range, eff_val)
    subtree:add(f_effwin_type, buf_range, calc_type)
    subtree:add(f_effwin_details, buf_range, details)
    subtree:add(f_cwnd_est, buf_range, math.floor(cwnd_est + 0.5))

    -- Add private fields for the TAP listener
    subtree:add(f_private_rwnd, buf_range, rwnd or 0)
    subtree:add(f_private_bif, buf_range, bytes_in_flight or 0)
    subtree:add(f_private_key, buf_range, key)

    -- Update Info column only on first pass
    if proto_eff.prefs.show_in_info and not pinfo.visited then
        local ok = pcall(function()
            pinfo.cols.info:append(string.format(" [EffWin:%d]", eff_val))
        end)
        if not ok then
            -- Column may be read-only in some cases, silently ignore
        end
    end
    
    return 0  -- Post-dissectors should return 0
end

-- TAP listener (created at global scope, but only processes when CSV enabled)
local tap_eff = Listener.new("tcp", "tcp.effwin.value")

local function tap_value_num(v)
    if not v then return nil end
    if type(v) == "table" and v.value then 
        return tonumber(tostring(v.value)) 
    end
    return tonumber(tostring(v))
end

local function tap_value_str(v)
    if not v then return nil end
    if type(v) == "table" and v.value then 
        return tostring(v.value)
    end
    return tostring(v)
end

function tap_eff.packet(pinfo, tvb, tapdata)
    -- Skip if CSV not enabled or file not open
    if not proto_eff.prefs.enable_csv or not csv_file then return end
    
    csv_pkt_counter = csv_pkt_counter + 1
    if (csv_pkt_counter % math.max(1, proto_eff.prefs.csv_every_n)) ~= 0 then return end

    -- Validate and read fields from tapdata
    if not tapdata then return end
    
    local key    = tap_value_str(tapdata["tcp.effwin.private.key"])
    local effwin = tap_value_num(tapdata["tcp.effwin.value"])
    local cwnd   = tap_value_num(tapdata["tcp.effwin.cwnd_est"])
    local rwnd   = tap_value_num(tapdata["tcp.effwin.private.rwnd"])
    local bif    = tap_value_num(tapdata["tcp.effwin.private.bif"])
    
    -- Skip if essential fields are missing
    if not key or not effwin then return end
    
    -- Safe CSV write with error handling
    local ok, err = pcall(function()
        csv_file:write(string.format("%.6f,%q,%d,%.0f,%d,%d\n", 
            pinfo.rel_ts or 0.0, 
            key,
            effwin or 0, 
            cwnd or 0, 
            rwnd or 0, 
            bif or 0))
        csv_file:flush()
    end)
    
    if not ok then
        print("TCP EffWin CSV write error: " .. tostring(err))
        if csv_file then
            pcall(function() csv_file:close() end)
            csv_file = nil
        end
    end
end

function tap_eff.reset()
    if csv_file then 
        pcall(function() csv_file:close() end)
        csv_file = nil 
    end
    conv_scale = {}
    flow_cwnd = {}
    csv_pkt_counter = 0
end

function proto_eff.init()
    -- Close any existing CSV file first
    if csv_file then
        pcall(function() csv_file:close() end)
        csv_file = nil
    end
    
    -- Reset state
    conv_scale = {}
    flow_cwnd = {}
    csv_pkt_counter = 0
    
    -- Open new CSV file if enabled
    if proto_eff.prefs.enable_csv then
        local ok, f = pcall(function() return io.open(proto_eff.prefs.csv_path, "w") end)
        if ok and f then
            csv_file = f
            local header_ok = pcall(function()
                csv_file:write("time,flow,effwin,cwnd_est,rwnd,bytes_in_flight\n")
                csv_file:flush()
            end)
            if not header_ok then
                print("TCP EffWin Warning: Could not write CSV header")
                pcall(function() csv_file:close() end)
                csv_file = nil
            end
        else
            csv_file = nil
            print("TCP EffWin Warning: Could not open CSV file: " .. tostring(proto_eff.prefs.csv_path))
        end
    end
end

function proto_eff.reset()
    if csv_file then 
        pcall(function() csv_file:close() end)
        csv_file = nil 
    end
    conv_scale = {}
    flow_cwnd = {}
    csv_pkt_counter = 0
end

-- Register the post-dissector
register_postdissector(proto_eff)





#######
===============================================================
 TCP EFFECTIVE WINDOW POST-DISSECTOR (Wireshark Lua Plugin)
===============================================================

File: tcp_efficient_window.lua
Author: Cace Cacem (2025)
Language: Lua (Wireshark 3.x / 4.x compatible)

---------------------------------------------------------------
 WHAT IT DOES
---------------------------------------------------------------

This plugin calculates an estimated TCP "Effective Window" for
each packet in a capture. The Effective Window represents how
much data the sender can still transmit, considering both the
receiver window (Rwnd) and a heuristic congestion window (Cwnd).

    EffectiveWindow = max(0, min(Rwnd, Cwnd_est) - BytesInFlight)

It helps diagnose flow control and congestion issues that are
not directly visible from standard TCP fields.

---------------------------------------------------------------
 FEATURES
---------------------------------------------------------------

 * Conversation-aware TCP Window Scaling
 * Heuristic Cwnd estimation
 * Displays [EffWin:x] in the Info column
 * Optional CSV export for graphing
 * Post-dissector safe and efficient
 * Compatible with Linux / macOS / Windows

---------------------------------------------------------------
 INSTALLATION
---------------------------------------------------------------

1. Copy the file:
     tcp_efficient_window.lua
   into your Wireshark plugins folder:

   - Linux:
       ~/.local/lib/wireshark/plugins/
       or /usr/lib/x86_64-linux-gnu/wireshark/plugins/<version>/
   - macOS:
       ~/Library/Application Support/Wireshark/Plugins/
   - Windows:
       %APPDATA%\Wireshark\plugins\

2. Restart Wireshark.

3. Check installation:
     Help -> About Wireshark -> Plugins
   You should see: tcp_efficient_window

---------------------------------------------------------------
 PREFERENCES
---------------------------------------------------------------

From Wireshark:
   Analyze -> Enabled Protocols -> tcp_efficient_window -> Preferences

   [x] Append to Info column        (default: ON)
   [x] Enable heuristic Cwnd        (default: ON)
   [ ] Enable CSV export            (default: OFF)
       CSV path: /tmp/tcp_effwin.csv
       Write every N packets: 1
       
   Edit → Preferences → Protocols → TCP_EFFICIENT_WINDOW       

---------------------------------------------------------------
 CSV OUTPUT (optional)
---------------------------------------------------------------

Format:
   time,flow,effwin,cwnd_est,rwnd,bytes_in_flight

Example:
   0.000123,10.0.0.1:443>10.0.0.2:52234,65535,65535,65535,0
   0.001202,10.0.0.1:443>10.0.0.2:52234,32768,65535,65535,32767

You can plot this using Excel, gnuplot, or matplotlib.

---------------------------------------------------------------
 PLOTTING IN EXCEL
---------------------------------------------------------------

1. Open Excel.
2. Go to File -> Open -> Browse -> select "All Files (*.*)".
3. Select the exported CSV file (e.g., tcp_effwin.csv).
4. Use the Text Import Wizard (if prompted):
      - Delimiter: Comma (,)
      - Data type: General
5. Insert -> Chart -> Scatter with Lines.
6. Set:
      X-axis = "time"
      Y-axis = "effwin" or "cwnd_est"
7. Add both series (EffWin and Cwnd) to visualize TCP flow control behavior.

---------------------------------------------------------------
 PLOTTING IN GNUPLOT
---------------------------------------------------------------

Example gnuplot script (save as plot_effwin.gnu):

    set title "TCP Effective Window Over Time"
    set xlabel "Time (seconds)"
    set ylabel "Window Size (bytes)"
    set grid
    set key top left
    plot "tcp_effwin.csv" using 1:3 with lines title "EffWin", \
         "tcp_effwin.csv" using 1:4 with lines title "Cwnd_est", \
         "tcp_effwin.csv" using 1:5 with lines title "Rwnd"

Run it:
    gnuplot> load 'plot_effwin.gnu'

The plot will show how the effective window changes in relation
to Cwnd and Rwnd throughout the connection.

---------------------------------------------------------------
 UNINSTALL
---------------------------------------------------------------

Delete the file from your plugins folder and restart Wireshark.


---------------------------------------------------------------
 END OF FILE
---------------------------------------------------------------
