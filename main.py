import tkinter as tk
from threading import Thread, Event
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP, Raw

# Global variables for thread control and communication
stop_event = Event()
packet_queue = Queue()
sniff_thread = None

# Callback function to process each packet
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        payload = ""
        
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
            except Exception:
                payload = "(Binary Data, unable to decode)"
        
        # Enqueue packet info for the GUI thread
        packet_info = (
            f"Source IP: {src_ip}\n"
            f"Destination IP: {dst_ip}\n"
            f"Protocol: {protocol}\n"
            f"Payload Data: {payload}\n"
            f"{'-' * 50}\n"
        )
        packet_queue.put(packet_info)

# Function to start sniffing in a separate thread
def start_sniffing_thread(interface=None):
    sniff(iface=interface, prn=packet_callback, store=0, stop_filter=lambda p: stop_event.is_set())

# Start packet sniffing
def start_sniffing():
    global sniff_thread
    print("Starting packet sniffing...")
    stop_event.clear()  # Clear the stop event in case it's set
    sniff_thread = Thread(target=start_sniffing_thread, args=(None,), daemon=True)
    sniff_thread.start()
    process_queue()  # Start processing the queue

# Stop packet sniffing
def stop_sniffing():
    global sniff_thread
    print("Stopping packet sniffing...")
    stop_event.set()  # Signal the sniffing thread to stop
    if sniff_thread:
        sniff_thread.join()  # Wait for the thread to terminate

# Process the packet queue and update the GUI
def process_queue():
    while not packet_queue.empty():
        packet_info = packet_queue.get()
        text_area.insert(tk.END, packet_info)
        text_area.yview(tk.END)  # Scroll to the end of the text area
    text_area.after(100, process_queue)  # Check the queue again after 100 ms

# Handle window close event
def on_closing():
    stop_sniffing()  # Ensure sniffing stops
    root.destroy()   # Close the GUI window

# Create GUI window
def create_gui():
    global text_area, root
    
    root = tk.Tk()
    root.title("Packet Sniffer")

    # Create a text area widget
    text_area = tk.Text(root, wrap='word', height=20, width=100)
    text_area.pack(expand=True, fill='both')

    # Create a start button to begin sniffing
    start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
    start_button.pack(pady=5)

    # Create a stop button to end sniffing
    stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing)
    stop_button.pack(pady=5)

    root.protocol("WM_DELETE_WINDOW", on_closing)  # Ensure sniffing stops when closing the window

    root.mainloop()

# Run the GUI
create_gui()
