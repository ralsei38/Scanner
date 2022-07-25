import pdb
import logging
import random
import sys
from scapy.all import sr1, srp,Ether,IP, ICMP, TCP

class Ip:
    def __init__(self, ip_str, netmask_str) -> None:
        
        if not isinstance(ip_str, str) or not isinstance(netmask_str, str):
            raise TypeError
        
        if len(ip_str.split('.')) != 4 or len(netmask_str.split('.')) != 4:
            raise ValueError
        
        self.ip_str = ip_str
        self.netmask_str = netmask_str
        self.is_up = False
        self.os = None
        self.name = None
        self.lastly_scanned = None
        self.open_ports = []

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
    
    def ping(self, timeout=1) -> bool:
        pkt = Ether()/IP(dst=self.ip_str)/ICMP(type=8, code=0)
        result, _ = srp(pkt, timeout=timeout)
        return len(result) == 1

    def tcp_Syn_scan(self) -> None:
        """
        TCP SYN request on host, stores result in open_ports attribute
        """
        for i in range(49151):
            if srp(Ether()/IP(dst=self.ip_str)/TCP(sport=random.randrange(49152, 64738), dport=i)):
                self.open_ports.append(i)

    def __str__(self) -> str:
        return self.ip_str

class Network:
    def __init__(self, ip: Ip) -> None:
        self.ip = ip
    
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
        return 2**n_free_bits - 1 # last IP broadcast, real number is 2**nb_free_bits-2


    def ping_scan(self, timeout=1) -> list:
        host_list = []
        for i in range(self.get_nb_max_host()):
            ip_iter = self.ip
            if ip_iter.ping(timeout):
                host_list.append(str(ip_iter))
            ip_iter.next()
            print(str(ip_iter))
        return host_list

if __name__ == "__main__":
    ip = Ip("192.168.1.1", "255.255.255.0")
    network = Network(ip)
    host_list = network.ping_scan(1)
    print(host_list)