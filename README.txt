===============================================================
 TCP EFFECTIVE WINDOW POST-DISSECTOR (Wireshark Lua Plugin)
===============================================================

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
