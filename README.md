# Packet Sniffer with Tkinter and Scapy

## How It Works

This packet sniffer application captures and displays network packets using Python. It leverages Tkinter for the graphical user interface (GUI) and Scapy for network packet capturing.

### Components

1. Tkinter GUI: Provides a user-friendly interface with buttons to start and stop packet sniffing. The GUI includes a text area where packet details are displayed.

2. Scapy Packet Sniffer: Handles the actual packet capturing. It runs in a separate thread to ensure that the GUI remains responsive.

### Functionality

1. Starting Packet Sniffing:
   - When the "Start Sniffing" button is clicked, a separate thread is created to run the packet sniffing process.
   - The `scapy.sniff()` function is used to capture packets. The `packet_callback` function processes each captured packet and extracts relevant information.

2. Processing Packets:
   - For each packet captured, the `packet_callback` function extracts the source IP, destination IP, protocol (TCP/UDP), and payload data.
   - This information is formatted and added to a queue.

3. Updating the GUI:
   - The `process_queue()` function periodically checks the queue for new packet information.
   - If there are any new packets, the function updates the text area in the GUI with the packet details.

4. Stopping Packet Sniffing:
   - When the "Stop Sniffing" button is clicked or the window is closed, the sniffing process is stopped by setting a global event flag.
   - The sniffing thread is then joined, ensuring it terminates before the application closes.

5. Graceful Exit:
   - The `on_closing` function ensures that packet sniffing stops when the window is closed, and the application exits cleanly.

### Summary

The application captures network packets and displays their details in a GUI window. The sniffing process runs in a separate thread to keep the GUI responsive, and the application can be stopped gracefully via the provided buttons or by closing the window.
