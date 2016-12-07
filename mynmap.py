#!/opt/SCAPY3/bin/python
from scapy.all import *

import argparse
import ipaddress

Dbound = 21
Ubound = 22
ip = ''
to = 5
def idle(ip, zombie):
   print ("please enter a valid IP")

def conn(ip):
   print ("please enter a valid IP")

def connect()
   for port in range(Dbound, Ubound):
      ans = sr1(IP(dst=ip)/TCP(dport=port,flags="S"), timeout=to,verbose=True)
      if str(ans) == "None":
         print("Port : " + port + " FILTERED " + prot(port))
      else if str(ans[TCP].flags) == "SA":
         print("Port : " + port + " OPEN " + prot(port))
         sr1(IP(dst=ip)/TCP(dport=port,flags="RA"), timeout=to, verbose=False)
   
def SYN():
   for port in range(Dbound, Ubound):
      ans = sr1(IP(dst=ip)/TCP(dport=port,flags="s"), timeout=to,verbose=True)
      if str(ans) == "None":
         print("Port : " + port + " FILTERED " + prot(port))
      else if str(ans[TCP].flags) == "SA":
         print("Port : " + port + " OPEN " + prot(port))
         sr1(IP(dst=ip)/TCP(dport=port,flags="R"), timeout=to, verbose=False)

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
       global ip
       ip = args.ip
    else:
        print ("please enter a valid IP")
        sys.exit()
        
    if args.conn:
        conn() #handshake
    elif args.xmas:
       xmas() # "FPU"
    elif args.idle:
        if ipOK(args.idle):
           idle(args.idle)
        else:
            print ("please enter a valid IP")
            sys.exit()
    elif args.fin:
        fin()#"F"
    elif args.null:
        null()
    else:
        syn() # "S"

if __name__ == "__main__":
    main()
