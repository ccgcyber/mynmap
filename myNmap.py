from Scanner import Scanner
from Network import Networking
import argparse

net = Networking()
filterLimit = 25
def parser():
    parse = argparse.ArgumentParser(description="recode of the nmap tool. default flag : -s")
    parse.add_argument("ip")
    parse.add_argument("-s", "--syn", help="Scan open port using SYN flag", action="store_true")
    parse.add_argument("-c","--conn", help="Scan open port using tcp connect", action="store_true")
    parse.add_argument("-x", "--xmas", help="Scan open port using FIN/URG/Push flag",action="store_true")
    parse.add_argument("-f", "--fin", help="Scan open port using FIN flag", action="store_true")
    parse.add_argument("-n","--null",help="Scan open port using NULL flag",action="store_true")
    parse.add_argument("-i","--idle", help="Scan open port using a zombie")
    return parse.parse_args()

def showResult(result, counter):
    print("PORT\t STATUS \tSERVICE")
    for port in result:
        if "FILTERED" in port and counter >= filterLimit:
            pass
        else:
            print (port)
    if counter >= filterLimit:
        print (str(filterLimit) + " port were filtered!")


def main():
   args = parser()

   global ip
   ip = net.getValidIp(args.ip)
   if ip == False:
      print ("please enter a valid IP")
      sys.exit()
   scanner = Scanner(args, ip);
   result, counter = scanner.scan()
   showResult(result, counter)

if __name__ == "__main__":
    main()
