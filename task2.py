from scapy.all import sniff, IP, TCP, UDP, Raw

# Function to process each captured packet
def packet_callback(packet):
    print("\n=== New Packet ===")
    
    if IP in packet:  # Check if packet has IP layer
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
        
        if TCP in packet:
            print("Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        
        elif UDP in packet:
            print("Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        
        # If packet has data payload
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                print(f"Payload: {payload[:100]}")  # Show first 100 chars
            except:
                print("Payload: [Could not decode]")
    else:
        print("Non-IP packet")

# Start sniffing (Ctrl+C to stop)
print("Starting packet capture... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, store=False)
