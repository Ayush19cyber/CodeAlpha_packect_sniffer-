import tkinter as tk  # Import Tkinter for creating the graphical user interface (GUI).
from scapy.all import sniff, IP, TCP  # Import Scapy to capture and process network packets.
from threading import Thread 
""" Threads allow different parts of your program to run at the same time. This is especially 
    useful when you have tasks that take a while to complete, like network sniffing,because it 
    lets the rest of the program continue running without getting stuck or waiting."""

# Callback function that processes each captured packet
def packet_callback(packet, text_widget):
    """ This function is called for each packet captured by the sniffer. It extracts relevant
        information from the packet, such as IP address and TCP details.The extracted data is 
        displayed in the provided text widget (GUI area) to show real-time packet information."""
    
# If the packet contains an IP layer, we extract the source and destination IP addresses
    if IP in packet:
        ip_src = packet[IP].src  # Source IP address of the packet
        ip_dst = packet[IP].dst  # Destination IP address of the packet

        # If the packet contains a TCP layer, extract source and destination ports
        if TCP in packet:
            tcp_sport = packet[TCP].sport  # Source port
            tcp_dport = packet[TCP].dport  # Destination port
            # Format the packet information to display IP and TCP details
            packet_info = f"IP: {ip_src} -> {ip_dst} (TCP: {tcp_sport} -> {tcp_dport})"
        else:
            # If it's an IP packet but not TCP, just show the IP addresses
            packet_info = f"IP: {ip_src} -> {ip_dst}"

        # Insert the formatted packet information into the GUI text widget
        text_widget.insert(tk.END, packet_info + "\n")
        text_widget.yview(tk.END)  # Automatically scroll the text widget to show the latest packet

# Function to start sniffing network packets
def start_sniffing(text_widget):
    """ Start the sniffing process, which continuously captures packets from the network
        text_widget: The Tkinter Text widget where the packet information will be displayed."""
    
    global stop_flag  # Access the global stop_flag variable
    stop_flag = False  # Reset the stop_flag before starting sniffing
    """These stop_flag used to sniffing stop or continue in set amount of time if the source code was mention in list"""
    # The sniff() function captures network packets. 
    # We use the stop_filter to stop sniffing when stop_flag is set to True.
    sniff(filter="ip", prn=lambda packet: packet_callback(packet, text_widget),  # Process each packet using packet_callback
          store=0,  # Don't store the packets in memory (we only need to display them)
          stop_filter=lambda x: stop_flag)  # Stop sniffing when stop_flag is True

# Function to stop the sniffing process
def stop_sniffing():
    """ Stops the packet sniffing by setting the stop_flag in True. 
        This will instruct the sniffer to stop capturing packets."""
    global stop_flag  # Access the global stop_flag variable
    stop_flag = True  # Set stop_flag to True, which will stop the sniffing in the next packet capture

# Create the main GUI window
root = tk.Tk()
root.title("Network Sniffer")  # Set the window title to "Network Sniffer"

# Create a Text widget to display the captured packet information in the GUI
text_widget = tk.Text(root, height=20, width=80)  # Define the size of the text box (height=20, width=80 characters)
text_widget.pack(padx=10, pady=10)  # Add the text widget to the window with padding around it

# Create a "Start Sniffer" button that will start the sniffing process when clicked
start_button = tk.Button(root, text="Start Sniffer", command=lambda: Thread(target=start_sniffing, args=(text_widget,)).start())
start_button.pack(side=tk.LEFT, padx=10, pady=10)  # Place the button on the left side of the window with padding

# Create a "Stop Sniffer" button that will stop the sniffing process when clicked
stop_button = tk.Button(root, text="Stop Sniffer", command=stop_sniffing)
stop_button.pack(side=tk.LEFT, padx=10, pady=10)  # Place the stop button next to the start button

# Start the Tkinter event loop, which listens for user interactions (like button clicks)
root.mainloop()
