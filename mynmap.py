#!/opt/SCAPY3/bin/python
# shebang used with virtual env

# prevent scapy from showing warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import conf

conf.verb = 0
from scapy.all import *

import argparse

import ipaddress

import socket
Dbound = 49151 # first port scanned minimum : 1
Ubound = 49154 # last port scanned maximum : 65536
ip = ''
time_out = 5
# Flag
SA = 18

def getZombieID(zombie):
   for port in range(1, 80):
      zpck = sr1(IP(dst=zombie)/TCP(dport=port,flags="S"), timeout=2)
      if str(type(zpck)) == "<class 'NoneType'>":
         id = -1
      else: 
         return zpck.id

def idle(zombie):
   for port in range(Dbound, Ubound):
      start = getZombieID(zombie)
      if start != -1: 
         sr1(IP(src=zombie, dst=ip)/TCP(dport=port,flags="S"), timeout=time_out)
         end = getZombieID(zombie)
         if end - start >= 2:
            print(str(port) + "\t OPEN \t" + protocoleMapping(port))

def protocoleMapping(port):
   try:
      protocol = socket.getservbyport(port)
      return protocol
   except OSError:
      return "UNKNOWN"
   
def genScan(flag):
   for port in range(Dbound, Ubound):
      ans = sr1(IP(dst=ip)/TCP(dport=port,flags=flag), timeout=time_out)
      if str(type(ans)) == "<class 'NoneType'>":
         print(str(port) + "\t OPEN \t" + protocoleMapping(port))
      elif ans[ICMP].type ==3 and ans[ICMP].code in [1,2,3,9,10,13]:
         print(str(port) + "\t FILTERED \t" + protocoleMapping(port))
     
def conn():
   for port in range(Dbound, Ubound):
      ans = sr1(IP(dst=ip)/TCP(dport=port,flags="S"), timeout=time_out)
      if str(type(ans)) == "<class 'NoneType'>":
         print(str(port) + "\t FILTERED \t" + protocoleMapping(port))
      elif ans[TCP].flags == SA:
         print(str(port) + "\t OPEN \t" + protocoleMapping(port))
         sr1(IP(dst=ip)/TCP(dport=port,flags="RA"), timeout=time_out)
         
def syn():
   for port in range(Dbound, Ubound):
      ans = sr1(IP(dst=ip)/TCP(dport=port,flags="S"), timeout=time_out)
      if str(type(ans)) == "<class 'NoneType'>":
         print(str(port) + "\t FILTERED \t" + protocoleMapping(port))
      elif ans[TCP].flags == SA:
         print(str(port) + "\t OPEN \t" + protocoleMapping(port))
         sr1(IP(dst=ip)/TCP(dport=port,flags="R"), timeout=time_out)
# Check if the ip given in parameter is a valid IP
def ipOK(s):
   try:
      t = ipaddress.ip_address(s)
   except ValueError:
      return False
   return True

# Allow the program time_out accept option from command line
def parser():
    parse = argparse.ArgumentParser(description="recode of the nmap tool. default flag : -s")
    parse.add_argument("ip")
    parse.add_argument("-s", "--syn", help="Scan open port using SYN flag", action="store_true")
    parse.add_argument("-c","--conn", help="Scan open port using tcp connect", action="store_true")
    parse.add_argument("-x", "--xmas", help="Scan open port using FIN/URG/Push flag",action="store_true")
    parse.add_argument("-f", "--fin", help="Scan open port using FIN flag", action="store_true")
    parse.add_argument("-n","--null",help="Scan open port using NULL flag",action="store_true")
    parse.add_argument("-i","--idle", help="Scan open port using zombie")
    return parse.parse_args()

def scan(args):
   if args.conn:
      conn() # TCP handshake syn -> syn/ack -> rst/ack
   elif args.xmas:
      genScan("FPU") # XMAS Scan
   elif args.idle:
      if ipOK(args.idle):
         idle(args.idle) # Scan anonymous with zombie
      else:
         print ("please enter a valid IP")
         sys.exit()
   elif args.fin:
      genScan("F") # FIN Scan
   elif args.null:
      genScan("") # NULL Scan
   else:
      syn() # Syn Scan
 
def main():
   args = parser()
   
   if ipOK(args.ip):
      # Give the value of the IP from option line to the ip variable in file
      global ip
      ip = args.ip
   else:
      print ("please enter a valid IP")
      sys.exit()
   print("PORT\t Status\t Service")   
   scan(args)
      
if __name__ == "__main__":
    main()
