# Disable Scapy Warning
import logging
from Network import Networking
from scapy.all import *
from scapy.all import conf
net = Networking()
conf.verb = 0

# NOTSET |DEBUG | INFO | WARNING | ERROR | CRITICAL
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

Dbound = 75 # first port scanned minimum : 1
Ubound = 86 # last port scanned maximum : 65535 +1
time_out = 1
SA = 18 # Flag SynAck code

class Scanner(object):
    args = None
    ip = None
    def __init__(self, args, ip):
        self.args = args
        self.ip = ip

    def scan(self):
        results = []
        counter = -1
        if self.args.conn:
            return self.conn() # TCP handshake syn -> syn/ack -> rst/ack
        elif self.args.xmas:
            return self.genScan("FPU") # XMAS Scan
        elif self.args.idle:
            ipIdle = net.getValidIp(self.args.ip)
            if ipIdle == False:
                print ("please enter a valid IP")
                sys.exit()
            return self.idle(ipIdle) # Scan anonymous with zombie
        elif self.args.fin:
            return self.genScan("F") # FIN Scan
        elif self.args.null:
            return self.genScan("") # NULL Scan
        else:
            return self.syn() # Syn Scan

    global send
    def send(self, port, flag):
        return sr1(IP(dst = self.ip) / TCP(dport = port, flags = flag), timeout = time_out)

    global sendZ
    def sendZ(self, port, flag, src):
        return sr1(IP(src = src, dst = self.ip) / TCP(dport = port, flags = flag), timeout = time_out)

    def genScan(self, flag):
        result = []
        counter = 0
        for port in range(Dbound, Ubound):
            ans = send(self, port, flag)
            if str(type(ans)) == "<class 'NoneType'>":
                result.append(str(port) + "\t OPEN \t\t" + net.protocoleMapping(port))
            elif ans[ICMP].type == 3 and ans[ICMP].code in [1, 2, 3, 9, 10, 13]:
                counter += 1
                result.append(str(port) + "\t FILTERED \t" + net.protocoleMapping(port))
        return result, counter

    def conn(self):
        result = []
        counter = 0
        for port in range(Dbound, Ubound):
            ans = send(self, port, "S")
            if str(type(ans)) == "<class 'NoneType'>":
                result.append(str(port) + "\t FILTERED \t" + net.protocoleMapping(port))
                counter += 1
            elif ans[TCP].flags == SA:
                result.append(str(port) + "\t OPEN \t\t" + net.protocoleMapping(port))
                send(self, port, "RA")
        return result, counter

    def syn(self):
        result = []
        counter = 0
        for port in range(Dbound, Ubound):
            ans = send(self, port, "S")
            if str(type(ans)) == "<class 'NoneType'>":
                result.append(str(port) + "\t FILTERED \t" + net.protocoleMapping(port))
                counter += 1
            elif ans[TCP].flags == SA:
                result.append(str(port) + "\t OPEN \t\t" + net.protocoleMapping(port))
                send(self, port, "R")
        return result, counter

    def idle(self, zombie):
        result = []
        for port in range(Dbound, Ubound):
            start = self.getZombieID(self, zombie)
            if start != -1:
                sendZ(self, port, "S", zombie)
                end = self.getZombieID(self, zombie)
            if end - start >= 2:
                result.append(str(port) + "\t OPEN \t\t" + net.protocoleMapping(port))
        return result, -1

    def getZombieID(self, zombie):
        for port in range(1, 80):
            zpck = sr1(IP(dst = zombie) / TCP(dport = port, flags = "S"), timeout = time_out)
            if str(type(zpck)) == "<class 'NoneType'>":
                id = -1
            else:
                return zpck.id
