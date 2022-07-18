import pdb
import logging
from scapy.all import sr1, srp,IP,ICMP,Ether
class Ip:
    def __init__(self, ip_str, netmask_str) -> None:
        
        if not isinstance(ip_str, str) or not isinstance(netmask_str, str):
            raise TypeError
        
        if len(ip_str.split('.')) != 4 or len(netmask_str.split('.')) != 4:
            raise ValueError
        
        self.ip_str = ip_str
        self.netmask_str = netmask_str
        self.is_up = False
    
    def next(self) -> None:
        ip_arr = [int(part) for part in self.ip_str.split('.')]
        for i in reversed(range(len(ip_arr))):
            if ip_arr[i] <= 254:
                ip_arr[i] += 1
                break
            else:
                ip_arr[i] = 0
                continue
        self.ip_str = ".".join([str(part) for part in ip_arr])

    def __str__(self) -> str:
        return self.ip_str
    
class Network:
    def __init__(self, ip: Ip) -> None:
        self.ip = ip
    
    def ping(self, ip_str) -> bool:
        pckt = Ether()/IP(dst=ip_str)/ICMP(type=8, code=0)
        pqt = sr1(pckt ,timeout=0.5)
        return pqt
    
    def get_nb_max_host(self) -> int:
        """
            How much hosts can this ip range could welcome
        """
        netmask_bin = ''.join([ format(int(part), '08b') for part in self.ip.netmask_str.split('.')])
        n_free_bits = 0
        for i in reversed(netmask_bin):
            if int(i) == 0:
                n_free_bits += 1
            else:
                break
        return 2**n_free_bits-1 # last IP broadcast, real number is 2**nb_free_bits-2


    def ping_scan(self) -> list:
        for i in range(self.get_nb_max_host()):
            ip_iter = self.ip
            self.ping(str(ip_iter))
            logging.debug(f"ping: {str(ip_iter)}")
            ip_iter.next()
        pass

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logging.debug("running scanner.py")
    logging.debug("creating ip object")
    ip = Ip("192.168.1.0", "255.255.255.0")
    logging.debug("creating Network object")
    network = Network(ip)
    network.ping_scan()    