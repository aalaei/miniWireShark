import time
import socket
from struct import unpack, pack
import textwrap
import platform
import binascii


class Pcap:

    def __init__(self, filename, link_type=1):
        self.pcap_fl = open(filename, 'wb')
        # pcap file header
        self.pcap_fl.write(pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        # header
        self.pcap_fl.write(pack('@ I I I I', ts_sec, ts_usec, len(data), len(data)))
        # raw data
        self.pcap_fl.write(data)

    def close(self):
        self.pcap_fl.close()


def hexify(data):
    return format(data, '02x')


def get_mac_addr(mac_raw):
    # byte_str = map('{:02x}'.format(), mac_raw)
    byte_str = map(hexify, mac_raw)
    # byte_str=mac_raw
    # [byte_str[i:i + 2] for i in range(0, len(byte_str), 2)]
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


def toIpv4(addr):
    return '.'.join(map(str, addr))


class IPv4:

    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 0xf) * 4
        self.ttl, self.proto, src, target = unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = toIpv4(src)
        self.target = toIpv4(target)
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
        self.src_port, self.dest_port, self.size, self.checkSum = unpack('! H H H H', raw_data[:8])
        self.data = raw_data[8:]


class ARP:

    def __init__(self, raw_data):
        self.Hardware_Type, self.ProtoclType, self.HardwareAdressSize, self.ProtocolAddressSize, self.Operation, self.Sender_MAC, self.Sender_IP, self.dst_mac, self.dst_IP = unpack(
            '2s 2s 1s 1s 2s 6s 4s 6s 4s', raw_data[:30])
        self.data = raw_data[28:]


class DnsQuery:
    Query_Name = ""
    Type = ""
    Class = ""


class RR:
    Name = ""
    Type = ""
    Class = ""
    TTL = 0
    Rdata_Length = 0
    Rdata = []


class DNS:
    def getRR(self, raw_data, count):
        last_j = 0
        rrs = [RR] * int(count)
        for i in range(int(count)):
            r = RR
            j = 0
            Name = ""
            a = raw_data[last_j + 1:]
            for j in range(len(a)):
                if raw_data[j + last_j + 1] == 0:
                    break

                if raw_data[j + last_j + 1] < 21:
                    Name = Name + "."
                else:
                    Name = Name + chr(raw_data[j + last_j + 1])

            last_j = j + last_j + 1
            dnsType, Class, ttl = unpack("! H H L", raw_data[last_j + 1:last_j + 9])
            Rdata_Length = raw_data[last_j + 5]
            Rdata = raw_data[last_j + 6:last_j + 6 + Rdata_Length]
            last_j = last_j + 6 + Rdata_Length
            r.Name = Name
            r.Class = Class
            r.Type = dnsType
            r.TTL = ttl
            r.Rdata_Length = Rdata_Length
            r.Rdata = Rdata
            rrs[i] = r

        return rrs, last_j

    def __init__(self, raw_data):
        self.indentification, self.control, self.Question_count, self.Answer_count, self.totalAuthority_RR, self.TotalAditional_RR = unpack(
            "! H H H H H H", raw_data[:12])
        ctl = self.control

        self.Rcode = ctl & 0b1111
        ctl = ctl >> 4

        self.CD = ctl & 0b1
        ctl = ctl >> 1

        self.AD = ctl & 0b1
        ctl = ctl >> 1

        self.Z = ctl & 0b1
        ctl = ctl >> 1

        self.RA = ctl & 0b1
        ctl = ctl >> 1

        self.RD = ctl & 0b1
        ctl = ctl >> 1

        self.TC = ctl & 0b1
        ctl = ctl >> 1

        self.AA = ctl & 0b1
        ctl = ctl >> 1

        self.Opcode = ctl & 0b1111
        ctl = ctl >> 4

        self.QR = ctl & 0b1
        ctl = ctl >> 1

        # questions
        last_j = 12
        questions = [DnsQuery] * int(self.Question_count)
        for i in range(int(self.Question_count)):
            d = DnsQuery
            j = 0

            Name = ""
            for j in range(len(raw_data[last_j + 1:])):
                if raw_data[j + last_j + 1] == 0:
                    break

                if raw_data[j + last_j + 1] < 21:
                    Name = Name + "."
                else:
                    Name = Name + chr(raw_data[j + last_j + 1])

            # Name = str(raw_data[last_j + 1:j + last_j + 1])
            last_j = j + last_j + 1
            dnsType = raw_data[last_j + 1]
            questionClass = raw_data[last_j + 2]
            last_j += 2
            d.Query_Name = Name
            d.Class = questionClass
            d.Type = dnsType
            questions[i] = d

            # d.Query_Name = unpack("! 4S 2s 2s", raw_data[12 + i, j])

        answers, last_j = self.getRR(raw_data[last_j + 1:], self.Answer_count)
        authorities, lastj = self.getRR(raw_data[last_j + 1:], self.totalAuthority_RR)
        additionalRRs, last_j = self.getRR(raw_data[last_j + 1:], self.TotalAditional_RR)

        self.answersRRs = answers
        self.aditionalRRs = additionalRRs
        self.authorityRRs = authorities
        self.questions = questions

        """
        self.QR, self.Opcode, self.AA, self.TC, self.RD, self.RA, self.z, self.AD, self.CD, self.Rcode = unpack(
            "! 1 3 1 1 1 1 1 1 1 3", self.control)
        """

        self.data = raw_data[last_j + 1:]


class HTTP:

    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data


class FTP:

    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('ascii')
        except:
            self.data = raw_data


def getIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def make_connection():
    if platform.system() == 'Windows':
        # if windows:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((str(getIP()), 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    elif platform.system() == "Linux":
        # if Linux
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    else:
        conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    return conn


def main():
    pcap = Pcap('captured.pcap')

    conn = make_connection()
    try:
        while True:

            raw_data, addr = conn.recvfrom(65535)
            pcap.write(raw_data)

            # ethernet
            eth = Ethernet(raw_data)
            print('\nEthernet Frame:')
            print('\t - ' + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

            # arp
            # if eth.proto == '\x08\x06':
            if eth.proto == 1544 or eth.proto == '\x08\x06':
                arp = ARP(eth.data)
                print("ARP_HEADER")
                print("Hardware type:   ", binascii.hexlify(arp.Hardware_Type))
                print("Protocol type:   ", binascii.hexlify(arp.ProtoclType))
                print("Hardware size:   ", binascii.hexlify(arp.HardwareAdressSize))
                print("Protocol size:   ", binascii.hexlify(arp.ProtoclType))
                print("Opcode:          ", binascii.hexlify(arp.Operation))
                print("Source MAC:      ", binascii.hexlify(arp.Sender_MAC))
                print("Source IP:      ", binascii.hexlify(arp.Sender_IP))
                print("Dest MAC:      ", binascii.hexlify(arp.dst_mac))
                print("Dest IP:      ", binascii.hexlify(arp.dst_IP))

                continue

            # IP
            if eth.proto == 8:
                ipv4 = IPv4(eth.data)
                print('\t - ' + 'IPv4 Packet:')
                print("\t" + '\t - ' + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length,
                                                                                     ipv4.ttl))
                print("\t" + '\t - ' + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

                # ICMP Protocol
                if ipv4.proto == 1:
                    icmp = ICMP(ipv4.data)
                    print('\t - ' + 'ICMP Packet:')
                    print("\t" + '\t - ' + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                    if icmp.type == 0:
                        print("Echo Reply")
                    elif icmp.type == 3:
                        print("Destination Unreachable")
                        if icmp.code == 0:
                            print("Net Unreachable")
                        elif icmp.code == 1:
                            print("HOST Unreachable")
                        elif icmp.code == 2:
                            print("Protocol Unreachable")
                        elif icmp.code == 3:
                            print("Port Unreachable")
                        elif icmp.code == 4:
                            print(" Cannot Fragment")
                        else:
                            print("Source Route Failed")

                    elif icmp.type == 4:
                        print("Source Quench")
                    elif icmp.type == 5:
                        print("Redirect")
                        if icmp.code == 0:
                            print("Redirect datagrams for the network")
                        elif icmp.code == 1:
                            print("Redirect datagrams for the host")
                        elif icmp.code == 2:
                            print("Redirect datagrams for the Type of Service and the network")
                        elif icmp.code == 3:
                            print("Redirect datagrams for the Type of Service and the host")

                    elif icmp.type == 8:
                        print("Echo Request")
                    elif icmp.type == 11:
                        print("Time Exceeded ")
                    elif icmp.type == 12:
                        print("Parameter Problem")
                    elif icmp.type == 13:
                        print("Timestamp request")
                    elif icmp.type == 14:
                        print("Timestamp reply ")
                    elif icmp.type == 15:
                        print("Information Request")

                    elif icmp.type == 16:
                        print("Information Reply")

                    elif icmp.type == 17:
                        print("Address mask request ")

                    elif icmp.type == 18:
                        print("Address mask response")

                    print("\t" + '\t - ' + 'ICMP Data:')
                    print(format_multi_line("\t\t\t   ", icmp.data))

                # TCP Protocol
                elif ipv4.proto == 6:
                    tcp = TCP(ipv4.data)
                    print('\t - ' + 'TCP Segment:')
                    print("\t" + '\t - ' + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                    print("\t" + '\t - ' + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                    print("\t" + '\t - ' + 'Flags:')
                    print("\t\t" + '\t - ' + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                    print("\t\t" + '\t - ' + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                    if len(tcp.data) > 0:

                        # HTTP
                        if tcp.src_port == 80 or tcp.dest_port == 80:
                            print("\t" + '\t - ' + 'HTTP Data:')
                            try:
                                http = HTTP(tcp.data)
                                http_info = str(http.data).split('\n')
                                for line in http_info:
                                    print("\t\t\t   " + str(line))
                            except:
                                print(format_multi_line("\t\t\t   ", tcp.data))
                        elif tcp.src_port == 27 or tcp.src_port == 28 or tcp.dest_port == 27 or tcp.dest_port == 28:

                            print("\t" + '\t - ' + 'FTP Data:')
                        try:
                            ftp = FTP(tcp.data)
                            ftp_info = str(ftp.data).split('\n')
                            for line in ftp_info:
                                print("\t\t\t   " + str(line))
                        except:
                            print(format_multi_line("\t\t\t   ", tcp.data))
                        else:
                            print("\t" + '\t - ' + 'TCP Data:')

                            print(format_multi_line("\t\t\t   ", tcp.data))


                # UDP Protocol
                elif ipv4.proto == 17:
                    udp = UDP(ipv4.data)
                    print('\t - ' + 'UDP Segment:')
                    print("\t" + '\t - ' + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port,
                                                                                                  udp.dest_port,
                                                                                                  udp.size))
                    # DNS Protocol
                    if udp.src_port == 53 or udp.dest_port == 53:
                        print("DNS Data: ")
                        try:
                            dns = DNS(udp.data)
                            print("Identification: {} ,Control: {}".format(dns.indentification, dns.control))
                            if dns.QR:
                                print("Response")
                            else:
                                print("Query")
                            print("num of Questions:{}".format(dns.Question_count))

                            print("num of Answers:{}".format(dns.Answer_count))
                            print("num of Authorities:{}".format(dns.totalAuthority_RR))
                            print("num of Additional RRs :{}".format(dns.TotalAditional_RR))
                            print("Questions: ")
                            print("------------------------")
                            qs = dns.questions
                            for q in qs:
                                print(q.Query_Name)

                            # print(dns.questions)
                            print("Answers:")
                            print("------------------------")
                            qs = dns.answersRRs
                            for q in qs:
                                print(q.Name)

                            # print(dns.answersRRs)
                            print("Authorities:")
                            print("------------------------")
                            qs = dns.authorityRRs
                            for q in qs:
                                print(q.Name)
                            # print(dns.authorityRRs)
                            print("Additional")
                            qs = dns.aditionalRRs
                            for q in qs:
                                print(q.Name)
                            # print(dns.aditionalRRs)
                            print("___________________________________")
                        except:
                            print(format_multi_line("\t\t\t   ", udp.data))
                    else:
                        print("UDP data:")
                        print(udp.data)

                # Other IPv4
                else:
                    print('\t - ' + 'Unknown IPv4 Data:')
                    print(format_multi_line("\t\t   ", ipv4.data))

            else:
                print('Ethernet Data:')
                print(format_multi_line("\t   ", eth.data))
    except:
        pass
    finally:
        pcap.close()


main()
