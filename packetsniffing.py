from scapy.all import sniff, IP, TCP, UDP, Raw
import sys

def process_packet(packet):
    try:
        # Check if the packet has an IP layer
        if IP in packet:
            ip_layer = packet[IP]
            transport_protocol = ''

            # Determine if the packet is TCP or UDP
            if packet.haslayer(TCP):
                transport_protocol = 'TCP'
            elif packet.haslayer(UDP):
                transport_protocol = 'UDP'

            # Extract the payload if present
            payload_data = packet[Raw].load if packet.haslayer(Raw) else None

            # Print packet details
            print(f"Source IP: {ip_layer.src}")
            print(f"Destination IP: {ip_layer.dst}")
            print(f"Protocol: {transport_protocol}")
            if payload_data:
                print(f"Payload: {payload_data}")
            print("\n")
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_packet_sniffing(network_interface=None):
    try:
        # Start packet sniffing on the specified interface
        sniff(iface=network_interface, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped by user.")
        sys.exit(0)
    except OSError as e:
        print(f"Error starting packet sniffing: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    import argparse

    # Argument parser for command-line options
    parser = argparse.ArgumentParser(description="A simple packet sniffer tool.")
    parser.add_argument('-i', '--interface', help="Network interface to sniff on (e.g., eth0, wlan0)")

    args = parser.parse_args()

    print("Starting packet sniffing...")
    print("Press Ctrl+C to stop...")

    # Start sniffing on the given interface (if provided)
    start_packet_sniffing(network_interface=args.interface)
