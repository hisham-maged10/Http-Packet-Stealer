import socket
import binascii
class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    ip = ""
    for i in range(len(raw_ip_addr)):
        ip += str(raw_ip_addr[i]) + "." if i != len(raw_ip_addr) -1 else str(raw_ip_addr[i])
    
    return ip


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # print("*****TCP PACKET PARSER*****")
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    packet_hexed = binascii.hexlify(ip_packet_payload)
    srcport = packet_hexed[0 : 4]
    srcport_dec = int(srcport, 16)
    destport = packet_hexed[4 : 8]
    destport_dec = int(destport, 16)
    dataoffset = packet_hexed[24 : 25]
    dataoffset_decimal = int(dataoffset, 16)
    payload_index = dataoffset_decimal * 4 * 2
    payload = packet_hexed[payload_index: ]
    payload_binary = binascii.unhexlify(payload)
    # print("srcport:", srcport_dec)
    # print("destport:", destport_dec)
    # print("dataoffset:", dataoffset_decimal)
    # print("TCP payload: ", payload_binary)
    return TcpPacket(srcport_dec, destport_dec, dataoffset_decimal, payload_binary)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    packet_hexed = binascii.hexlify(ip_packet)
    ihl = packet_hexed[1:2]
    ihl_dec = int(ihl,16)
    bytes_offset = (ihl_dec * 32) / 8
    payload_hex_idx = bytes_offset * 2
    protocol = packet_hexed[18:20]
    protocol_dec = int(protocol,16)
    src_addr = packet_hexed[24:32]
    src_addr_decoded = parse_raw_ip_addr(binascii.unhexlify(src_addr))
    dest_addr = packet_hexed[32:40]
    dest_addr_decoded = parse_raw_ip_addr(binascii.unhexlify(dest_addr))
    payload = packet_hexed[int(payload_hex_idx):]
    payload_binary = binascii.unhexlify(payload)
    # print(f'protocol: {protocol_dec}')
    # print(f'ihl: {ihl_dec}')
    # print(f'src_addr: {src_addr_decoded}')
    # print(f'dest_addr: {dest_addr_decoded}')
    # print(f'payload: {payload_binary}')
    ip_packet = IpPacket(protocol_dec,ihl_dec,src_addr_decoded,dest_addr_decoded,payload_binary) 
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    
    return ip_packet


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    
    stealer = socket.socket(socket.AF_INET,socket.SOCK_RAW,6) #protocol 6 for TCP
    iface_name = "lo"
    stealer.setsockopt(socket.SOL_SOCKET,
                       socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    while True:
        packet, _ = stealer.recvfrom(4096) #4096 buffer size #returned string, address , packet is the ip packet
        ip_packet = parse_network_layer_packet(packet)
        #starting from here da enta, b3tlk parse al payload bt3 al ip al hwa al TCP Segment (data packet) w ht3ml parse zye kda w t-print al payload bt3 al message
        tcp_packet = parse_application_layer_packet(ip_packet.payload)
        print(f"Sent from [{ip_packet.source_address}]\nTCP PAYLOAD: {tcp_packet.payload}")
        pass
    pass


if __name__ == "__main__":
    main()
