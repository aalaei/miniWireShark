import time
import socket
from struct import unpack, pack
import textwrap

TAB = '\t - '


class Pcap:

    def __init__(self, filename, link_type=1):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()

def hexify(data):
    return format(data,'02x')

def get_mac_addr(mac_raw):
    #byte_str = map('{:02x}'.format(), mac_raw)
    byte_str = map(hexify, mac_raw)
    #byte_str=mac_raw
    #[byte_str[i:i + 2] for i in range(0, len(byte_str), 2)]
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


class Ethernet:

    def __init__(self, raw_data):
        dest, src, prototype = unpack('! 6s 6s H', raw_data[:14])

        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]


class IPv4:

    def ipv4(self, addr):
        return '.'.join(map(str, addr))

    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 0xf) * 4
        self.ttl, self.proto, src, target = unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.ipv4(src)
        self.target = self.ipv4(target)
        self.data = raw_data[self.header_length:]


class ICMP:

    def __init__(self, raw_data):
        self.type, self.code, self.checksum = unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]


class TCP:

    def __init__(self, raw_data):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = unpack(
            '! H H L L H', raw_data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.data = raw_data[offset:]


class UDP:

    def __init__(self, raw_data):
        self.src_port, self.dest_port, self.size = unpack('! H H 2x H', raw_data[:8])
        self.data = raw_data[8:]


class HTTP:

    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data


def main():
    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    try:
        while True:

            raw_data, addr = conn.recvfrom(65535)
            pcap.write(raw_data)

            # ethernet
            eth = Ethernet(raw_data)

            print('\nEthernet Frame:')
            print(TAB + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

            # IP
            if eth.proto == 8:
                ipv4 = IPv4(eth.data)
                print(TAB + 'IPv4 Packet:')
                print("\t" + TAB + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length,
                                                                                     ipv4.ttl))
                print("\t" + TAB + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

                # ICMP Protocol
                if ipv4.proto == 1:
                    icmp = ICMP(ipv4.data)
                    print(TAB + 'ICMP Packet:')
                    print("\t" + TAB + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                    print("\t" + TAB + 'ICMP Data:')
                    print(format_multi_line("\t\t\t   ", icmp.data))

                # TCP Protocol
                elif ipv4.proto == 6:
                    tcp = TCP(ipv4.data)
                    print(TAB + 'TCP Segment:')
                    print("\t" + TAB + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                    print("\t" + TAB + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                    print("\t" + TAB + 'Flags:')
                    print("\t\t" + TAB + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                    print("\t\t" + TAB + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                    if len(tcp.data) > 0:

                        # HTTP
                        if tcp.src_port == 80 or tcp.dest_port == 80:
                            print("\t" + TAB + 'HTTP Data:')
                            try:
                                http = HTTP(tcp.data)
                                http_info = str(http.data).split('\n')
                                for line in http_info:
                                    print("\t\t\t   " + str(line))
                            except:
                                print(format_multi_line("\t\t\t   ", tcp.data))
                        else:
                            print("\t" + TAB + 'TCP Data:')
                            print(format_multi_line("\t\t\t   ", tcp.data))


                # UDP Protocol
                elif ipv4.proto == 17:
                    udp = UDP(ipv4.data)
                    print(TAB + 'UDP Segment:')
                    print("\t" + TAB + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port,
                                                                                                  udp.dest_port,
                                                                                                  udp.size))

                    if udp.src_port == 53 or udp.dest_port == 53:
                        print ("DNS Data: ")
                        try:
                            http = HTTP(udp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print("\t\t\t   " + str(line))
                        except:
                            print(format_multi_line("\t\t\t   ", udp.data))
                    else:
                        print("UDP data:")
                        print(udp.data)

                # Other IPv4
                else:
                    print(TAB + 'Unknown IPv4 Data:')
                    print(format_multi_line("\t\t   ", ipv4.data))

            else:
                print('Ethernet Data:')
                print(format_multi_line("\t   ", eth.data))
    except:
        pass
    finally:
        pcap.close()


main()
