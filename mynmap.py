#!/opt/SCAPY3/bin/python
from scapy.all import *

import argparse
import ipaddress


bound = 65535
ip = ' '

def idle(ip, zombie):
   print ("please enter a valid IP")

def conn(ip):
   print ("please enter a valid IP")

def loop(fl):
   for port in range(1, bound):
      pck = IP(dst = ip) / TCP(dport = port, flag = fl)
      sr1(pck)
    
    
def ipOK(s):
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return True

def main():
    parser = argparse.ArgumentParser(description="recode of the nmap tool. default flag : -s")
    parser.add_argument("-s", "--syn", help="Scan open port using SYN flag", action="store_true")
    parser.add_argument("-i","--idle", help="Scan open port using zombie", choices=["IP"])
    parser.add_argument("-c","--conn", help="Scan open port using tcp connect", action="store_true")
    parser.add_argument("-x", "--xmas", help="Scan open port using FIN/URG/Push flag",action="store_true")
    parser.add_argument("-f", "--fin", help="Scan open port using FIN flag", action="store_true")
    parser.add_argument("-n","--null",help="Scan open port using NULL flag",action="store_true")
    parser.add_argument("ip")
    args = parser.parse_args()
    
    if ipOK(args.ip):
        ip = args.ip
    else:
        print ("please enter a valid IP")
        sys.exit()
        
    if args.conn:
        conn(ip)
    elif args.idle:
        idle(ip, args.idle)
    elif args.xmas:
        if ipOK(args.xmas):
            loop(ip, "FPU")
        else:
            print ("please enter a valid IP")
            sys.exit()
    elif args.fin:
        loop("F")
    elif args.null:
        loop("")
    else:
        loop("S")

if __name__ == "__main__":
    main()
