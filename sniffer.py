import socket
import struct

def basic_sniffer():
    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("Sniffer started. Listening for packets...")

        while True:
            raw_packet, addr = sniffer.recvfrom(65535)

            eth_header = raw_packet[0:14]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol == 8:  
                ip_header = raw_packet[14:34]
                iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                ttl = iph[5]
                protocol = iph[6]
                src_ip = socket.inet_ntoa(iph[8])
                dst_ip = socket.inet_ntoa(iph[9])

                print(f"Source: {src_ip} → Destination: {dst_ip} | Protocol: {protocol} | TTL: {ttl}")

    except KeyboardInterrupt:
        print("\n🛑 Stopping sniffer.")
        sniffer.close()

if __name__ == "__main__":
    basic_sniffer()
