import dpkt, struct, binascii, sys

def main(filename):
    one_exchange = False
    print("\nARP Exchange")
    for ts, pkt in dpkt.pcap.Reader(open(filename, 'rb')):
         eth_type = struct.unpack('!h', pkt[12:14])
         #filter for ARP packet
         
         if eth_type[0] == 2054:
            if pkt[0:6].hex() != 'ffffffffffff':    #filter out broadcast packets
                arp_info = [0]*9
                opcode = struct.unpack('!h', pkt[20:22])
                
                #identifying request or reply packet
                if opcode[0]==1:
                     print("\tARP Request:")
                     arp_info[4] = "request (1)"
                elif opcode[0]==2:
                    print("\tARP Reply:")
                    arp_info[4] = "reply (1)"
                    one_exchange = True
                    
                #double checking codes for hardware/protocol type
                if struct.unpack('!h', pkt[14:16])[0]==1:
                    arp_info[0] = "Ethernet (1)"
                if struct.unpack('!h', pkt[16:18])[0]==2048:
                    arp_info[1] = "IPv4 (0x0800)"

                #hardware/protocol size values
                arp_info[2] = pkt[18]
                arp_info[3] = pkt[19]

                #mac addresses
                s_mac = pkt[22:28].hex()
                arp_info[5] = "{}:{}:{}:{}:{}:{}".format(s_mac[0:2],s_mac[2:4],s_mac[4:6],s_mac[6:8],s_mac[8:10],s_mac[10:])
                t_mac = pkt[32:38].hex()
                arp_info[7] = "{}:{}:{}:{}:{}:{}".format(t_mac[0:2],t_mac[2:4],t_mac[4:6],t_mac[6:8],t_mac[8:10],t_mac[10:])

                #IP addresses
                arp_info[6] = hex_to_ip(pkt[28:32].hex())
                arp_info[8] = hex_to_ip(pkt[38:42].hex())

                print_msg(arp_info)

                if one_exchange:
                    sys.exit(0)
               

def print_msg(msg):
    print("\t\tHardware type: ",msg[0])
    print("\t\tProtocol type: ",msg[1])
    print("\t\tHardware size: ",msg[2])
    print("\t\tProtocol size: ",msg[3])
    print("\t\tOpcode: ",msg[4])
    print("\t\tSender MAC address: ",msg[5])
    print("\t\tSender IP address: ",msg[6])
    print("\t\tTarget MAC address: ",msg[7])
    print("\t\tTarget IP address: ",msg[8])
    print("\n")

def hex_to_ip(h):
    #utility function to convert hex to ip format
    h_str = "{}:{}:{}:{}".format(h[0:2],h[2:4],h[4:6],h[6:])
    h_bytes = h_str.split(':')
    h_bytes = [int(x,16) for x in h_bytes]
    return ".".join(str(x) for x in h_bytes)
    
if __name__ == '__main__':
    main(sys.argv[1])
