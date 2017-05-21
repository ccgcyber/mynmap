import socket

class Networking(object):

    def validIpCheck(self, s):
        pieces = s.split('.')
        if len(pieces) != 4: return False
        try:
            return all(0 <= int(p) < 256 for p in pieces)
        except ValueError:
            return False

    def domainToIp(self, s):
        ip = ""
        try:
            ip = socket.gethostbyname(s)
        except socket.gaierror:
            return False
        except UnicodeError:
            return False
        return ip

    def getValidIp(self, s):
        ipCheck = self.validIpCheck(s)
        dnsConvert = self.domainToIp(s)
        if ipCheck == False and dnsConvert == False:
            return False
        elif ipCheck == False:
            return dnsConvert
        else:
            return ipCheck


    def protocoleMapping(self, port):
        try:
            protocol = socket.getservbyport(port)
            return protocol
        except OSError:
            return "UNKNOWN"
