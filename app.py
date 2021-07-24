
import optparse
import re
import socket
import struct
import time
from datetime import datetime


# Parse Packets
class IPv4:

    def __init__(self, r_data):
        tmp = []
        tmp = struct.unpack("! B B H H H B B H L L", r_data[:20])
        version_header_length = tmp[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.tos = tmp[1]  # type of service
        self.total_length = tmp[2]
        self.ID = tmp[3]
        ff = tmp[4]
        self.Rb = (ff & 0x8000) >> 15
        self.MF = (ff & 0x3FFF) >> 13
        self.DF = (ff & 0x7FFF) >> 14
        self.fragment_Offset = (ff & 0x1FFF)
        self.ttl = tmp[5]
        self.protocol = tmp[6]
        self.header_checksum = tmp[7]

        self.source_address = socket.inet_ntoa(struct.pack(">I", tmp[8]))
        self.destination_address = socket.inet_ntoa(struct.pack(">I", tmp[9]))
        self.options = []
        if self.header_length > 20:
            self.options = r_data[20:self.header_length]
        self.data = r_data[self.header_length:]


class TCP:
    def __init__(self, r_data):
        tmp = []
        tmp = struct.unpack('! H H L L H H H H', r_data[:20])
        self.src_port = tmp[0]
        self.dest_port = tmp[1]
        self.sequence = tmp[2]
        self.acknowledgment = tmp[3]
        offset_reserved_flag = tmp[4]
        self.window = tmp[5]
        self.checksum = tmp[6]
        self.urgent = tmp[7]
        self.offset = (offset_reserved_flag >> 12) * 4  # offset is header_length = row count * 32 / 8
        self.Reserved = (offset_reserved_flag & 0xE00) >> 9
        self.NS = (offset_reserved_flag & 256) >> 8
        self.CWR = (offset_reserved_flag & 128) >> 7
        self.ECE = (offset_reserved_flag & 64) >> 6
        self.URG = (offset_reserved_flag & 32) >> 5
        self.ACK = (offset_reserved_flag & 16) >> 4
        self.PSH = (offset_reserved_flag & 8) >> 3
        self.RST = (offset_reserved_flag & 4) >> 2
        self.SYN = (offset_reserved_flag & 2) >> 1
        self.FIN = (offset_reserved_flag & 1)
        self.options = []
        if self.offset > 20:
            self.options = r_data[20:self.offset]
        self.data = r_data[self.offset:]


class ICMP:
    def __init__(self, r_data):
        self.icmp_type, self.code, self.checksum, self.id, self.sequence = struct.unpack('! B B H H H', r_data[:8])
        self.data = r_data[8:]


# Create Packet
class Packet():
    def __init__(self, src_ip, dest_ip, port, mode):
        self.src_ip = src_ip
        self.dest_ip = dest_ip  # ip is string and addr is bytelike
        self.port = port
        self.mode = mode
        self.header = self.Create_IP() + self.Create_TCP()

    # IP header
    def Create_IP(self):
        version = 4
        header_length = 5
        version_header_length = (version << 4) + header_length
        tos = 0  # type of service
        total_length = 20 + 20
        ID = 0xabab
        flags_fragment_offset = 0
        ttl = 64
        protocol = 6  # TCP
        header_checksum = 0
        self.source_address = struct.unpack("!I", socket.inet_aton(self.src_ip))[0]
        self.destination_address = struct.unpack("!I", socket.inet_aton(self.dest_ip))[0]

        tmp_ip_header = struct.pack("! B B H H H B B H L L", version_header_length, tos, total_length, ID, flags_fragment_offset, ttl, protocol, header_checksum,
                                    self.source_address,
                                    self.destination_address)
        ip_header = struct.pack("! B B H H H B B H L L", version_header_length, tos, total_length, ID, flags_fragment_offset, ttl, protocol,
                                self.cal_checksum(tmp_ip_header),self.source_address, self.destination_address)

        return ip_header

    # TCP header
    def Create_TCP(self):
        src_port = 1234
        dest_port = self.port
        sequence = 0
        acknowledgment = 0

        window = 250
        checksum = 0
        urgent = 0
        offset = 5
        Reserved = NS = CWR = ECE = URG = PSH = RST = 0
        ACK = SYN = FIN = 0

        if self.mode == 'SS':
            SYN = 1

        if self.mode == 'AS' or self.mode == 'WS':
            ACK = 1

        if self.mode == 'FS':
            FIN = 1

        flags = (ACK << 4) + (PSH << 3) + (RST << 2) + (SYN << 1) + FIN
        offset_reserved_flag = (offset << 12) + flags

        tmp_tcp_header = struct.pack('! H H L L H H H H', src_port, dest_port, sequence, acknowledgment, offset_reserved_flag, window, checksum, urgent)
        tmp_header = struct.pack("!L L B B H", self.source_address, self.destination_address, 0, 6, len(tmp_tcp_header))  # check sum = 0, proto = 6
        H = tmp_header + tmp_tcp_header
        tcp_header = struct.pack('! H H L L H H H H', src_port, dest_port, sequence, acknowledgment, offset_reserved_flag, window, self.cal_checksum(H), urgent)

        return tcp_header

    def cal_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff

        return s


class Port_scanner():
    def __init__(self, src_ip, dest_ip, first_port, last_port, delay):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.start_port = first_port
        self.end_port = last_port
        self.delay = delay
        self.open = set()
        self.close = set()
        self.filtered = set()
        self.unfiltered = set()
        self.open_or_filtered = set()
        self.tmp = set([1,2,3,9,10,13])

    def Connect_Scan(self):
        print('Starting scan at {}'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())))
        for port in range(self.start_port, self.end_port + 1):
            try:
                tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(self.delay)
                if not tcp.connect((self.dest_ip, port)):
                    self.open.add(port)
                    tcp.close()
                else:
                    self.close.add(port)
                    tcp.close()

            except Exception:
                self.close.add(port)
                pass
        self.print_result('CS')



    def ACK_Scan(self):
        print('Starting scan at {}'.format(datetime.now()))
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        for port in range(self.start_port, self.end_port + 1):
            flag = 0
            packet = Packet(self.src_ip, self.dest_ip, port, 'AS')
            conn.sendto(packet.header, (self.dest_ip, 0))
            start_time = time.time()
            conn2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

            while time.time() - start_time < self.delay:
                try:
                    conn2.settimeout(self.delay)
                    raw_data, address = conn2.recvfrom(65535)
                    conn2.settimeout(None)
                    ipv4 = IPv4(raw_data[14:])
                    if ipv4.source_address == self.dest_ip:
                        if ipv4.protocol == 6:
                            tcp = TCP(ipv4.data)
                            if tcp.src_port == port and tcp.dest_port == 1234:
                                if tcp.RST == 1:  # RST -> unfiltered
                                    self.unfiltered.add(port)
                                    flag = 1
                                    break
                        #   create icmp and check if type==3 and code =1,2,3,9,10,13
                        if ipv4.protocol == 1:  # ICMP unreachable
                            icmp = ICMP(ipv4.data)
                            if icmp.icmp_type == 3 and icmp.code in self.tmp:
                                self.filtered.add(port)
                                flag = 1
                                break

                except socket.timeout as error:
                    self.filtered.add(port)
                    flag = 1
                    pass
            if flag == 0:
                self.filtered.add(port)

        self.print_result('AS')



    def FIN_Scan(self):
        print('Starting scan at {}'.format(datetime.now()))
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        for port in range(self.start_port, self.end_port + 1):
            flag = 0
            packet = Packet(self.src_ip, self.dest_ip, port, 'FS')
            conn.sendto(packet.header, (self.dest_ip, 0))
            start_time = time.time()
            conn2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

            while time.time() - start_time < self.delay :
                try:
                    conn2.settimeout(self.delay)
                    raw_data, address = conn2.recvfrom(65535)
                    conn2.settimeout(None)
                    ipv4 = IPv4(raw_data[14:])
                    if ipv4.source_address == self.dest_ip:
                        if ipv4.protocol == 6:
                            tcp = TCP(ipv4.data)
                            if tcp.src_port == port and tcp.dest_port == 1234:
                                if tcp.RST == 1:  # RST -> closed
                                    self.unfiltered.add(port)
                                    flag =1
                                    break
                        #   create icmp and check if type==3 and code =1,2,3,9,10,13
                        if ipv4.protocol == 1:  # ICMP unreachable
                            icmp = ICMP(ipv4.data)
                            if icmp.icmp_type == 3 and icmp.code in self.tmp:
                                self.filtered.add(port)
                                flag = 1
                                break

                except socket.timeout as error:
                    self.open_or_filtered.add(port)
                    flag = 1
                    pass

            if flag == 0:
                self.open_or_filtered.add(port)
        self.print_result('FS')



    def Window_Scan(self):
        print('Starting scan at {}'.format(datetime.now()))
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        for port in range(self.start_port, self.end_port + 1):
            flag = 0
            packet = Packet(self.src_ip, self.dest_ip, port, 'WS')
            conn.sendto(packet.header, (self.dest_ip, 0))
            start_time = time.time()
            conn2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

            while time.time() - start_time < self.delay :
                try:
                    conn2.settimeout(self.delay)
                    raw_data, address = conn2.recvfrom(65535)
                    conn2.settimeout(None)
                    ipv4 = IPv4(raw_data[14:])
                    if ipv4.source_address == self.dest_ip:
                        if ipv4.protocol == 6:
                            tcp = TCP(ipv4.data)
                            if tcp.src_port == port and tcp.dest_port == 1234:
                                if (tcp.RST == 1) and (tcp.window != 0):  # RST response with non-zero window  -> open
                                    self.open.add(port)
                                    flag = 1
                                    break

                                elif (tcp.RST == 1) and (tcp.window == 0):  # RST response with zero window  -> closed
                                    self.close.add(port)
                                    flag = 1
                                    break
                        #   create icmp and check if type==3 and code =1,2,3,9,10,13
                        if ipv4.protocol == 1:  # ICMP unreachable
                            icmp = ICMP(ipv4.data)
                            if icmp.icmp_type == 3 and icmp.code in self.tmp:
                                self.filtered.add(port)
                                flag =1
                                break

                except socket.timeout as error:
                    self.filtered.add(port)
                    flag = 1
                    pass

            if flag == 0:
                self.filtered.add(port)

        self.print_result('WS')



    def Syn_Scan(self):
        print('Starting scan at {}'.format(datetime.now()))
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        for port in range(self.start_port, self.end_port + 1):
            flag = 0
            packet = Packet(self.src_ip, self.dest_ip, port, 'SS')
            conn.sendto(packet.header, (self.dest_ip, 0))
            start_time = time.time()
            conn2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

            while time.time() - start_time < self.delay:
                try:
                    conn2.settimeout(self.delay)
                    raw_data, address = conn2.recvfrom(65535)
                    conn2.settimeout(None)
                    ipv4 = IPv4(raw_data[14:])
                    if ipv4.source_address == self.dest_ip:
                        if ipv4.protocol == 6:
                            tcp = TCP(ipv4.data)
                            if tcp.src_port == port and tcp.dest_port == 1234:
                                if tcp.ACK and tcp.SYN:  # SYN ACK -> open
                                    self.open.add(port)
                                    flag = 1
                                    break

                                elif tcp.RST == 1:  # RST -> closed
                                    self.close.add(port)
                                    flag = 1
                                    break
                        #   create icmp and check if type == 3 and code = 1,2,3,9,10,13
                        if ipv4.protocol == 1:  # ICMP unreachable
                            icmp = ICMP(ipv4.data)
                            if icmp.icmp_type == 3 and icmp.code in self.tmp:
                                self.filtered.add(port)
                                flag = 1
                                break

                except socket.timeout as error:
                    flag = 1
                    self.filtered.add(port)

                    continue

            if flag == 0:
                self.filtered.add(port)

        self.print_result('SS')


    def print_result(self, mode):
        print('\nscan report for {} in {} mode '.format(self.dest_ip,mode))
        print()

        print('{: <10} {: <15} {}'.format('PORT','STATE','SERVICE'))
        for port in range(self.start_port, self.end_port + 1):

            try:
                service = str(socket.getservbyport(port))
            except:
                service = '---'


            if port in self.open:
                print('{: <10} {: <15} {}'.format(port, 'open', service))

            elif port in self.close:
                print('{: <10} {: <15} {}'.format(port, 'close', service))

            elif port in self.filtered:
                print('{: <10} {: <15} {}'.format(port, 'filtered', service))

            elif port in self.unfiltered:
                print('{: <10} {: <15} {}'.format(port, 'unfiltered', service))

            elif port in self.open_or_filtered:
                print('{: <10} {: <15} {}'.format(port, 'open | filtered', service))



def main():
    parser = optparse.OptionParser(usage="%prog -t <IP or URL> -p <min-max> -s <scan mode> -d <delay>")
    parser.add_option("-t", "--target", dest="target", type="string", help="input target hostname")
    parser.add_option("-p", "--port-range", dest="port_range", type="string", help="input range in format 'min-max'")
    parser.add_option("-s", "--scan-mode", dest="scan_mode", type="string", help="CS => Connect Scan \n AS => Ack Scan \n "
                                                                                 "SS => Syn Scan \n FS => Fin Scan \n WS => Window Scan ")
    parser.add_option("-d", "--delay", dest="delay", type="float", help="delay for input packets")

    (options, args) = parser.parse_args()

    print("\ntarget: {}, ports: {}, mode: {}, delay: {}".format(options.target, options.port_range, options.scan_mode, options.delay))
    targetMatch = re.search("[a-zA-Z0-9]+[.:]*[\/]*", options.target)

    # validate target address
    if not targetMatch:
        parser.error('invalid args; see app.py -h for help')
    try:
        s = socket.gethostbyname(options.target)
        if not re.search("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", s):
            parser.error('invalid args; see app.py -h for help')
    except:
        parser.error('invalid arg target; see app.py -h for help')

    # validate ports range
    if not re.search("^(6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4})$", options.port_range):
        parser.error('invalid arg port_range; see app.py -h for help')

    # validate scan_mode

    if not re.search("^[CASFW]{1}[S]{1}$", options.scan_mode):
        parser.error('invalid arg scan_mode; see app.py -h for help')

    # validation delay

    if options.delay < 0:
        parser.error('invalid arg delay; see app.py -h for help')

    dest_ip = socket.gethostbyname(options.target)
    ports = options.port_range.split("-")
    min = int(ports[0])
    max = int(ports[1])
    mode = options.scan_mode
    delay = options.delay

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    my_ip = s.getsockname()[0]

    scanner = Port_scanner(my_ip, dest_ip, min, max, delay)

    if mode == 'CS':
        scanner.Connect_Scan()

    if mode == 'AS':
        scanner.ACK_Scan()

    if mode == 'SS':
        scanner.Syn_Scan()

    if mode == 'FS':
        scanner.FIN_Scan()

    if mode == 'WS':
        scanner.Window_Scan()


main()
