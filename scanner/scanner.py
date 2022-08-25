import pdb
import random
import sys
import threading
from time import sleep
import logging
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(level=logging.DEBUG)

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

    def next(self) -> str:
        ip_arr = [int(part) for part in self.ip_str.split('.')]
        for i in reversed(range(len(ip_arr))):
            if ip_arr[i] <= 254:
                ip_arr[i] += 1
                break
            else:
                ip_arr[i] = 0
                continue
        self.ip_str = ".".join([str(part) for part in ip_arr])
        return self.ip_str

    def ping(self, timeout=1) -> bool:
        pkt = IP(dst=self.ip_str)/ICMP(type=8, code=0)
        result, _ = sr(pkt, timeout=timeout, verbose=False)
        return len(result)

    def tcp_single_probe(self, port, scan_type="full", pkt=None, timeout=1) -> bool:
        if pkt is not None:
            raise NotImplementedError(f"Not processing the pkt parameter for now.")
        
        pkt = IP(dst=self.ip_str)/TCP(flags='S', dport=port)
        result, _ = sr(pkt, timeout=2, verbose=False)
        if "full" in scan_type:
            if len(result):
                print(len(result))
                print(result)
                logging.debug(f"TCP SYN attempt => SUCESSFULL => on {self.ip_str} port {port}")
                logging.debug(f"sending TCP ACK attempt on {self.ip_str} port {port}")
                send(Ether()/IP(dst=self.ip_str)/TCP(sport=random.randrange(49152, 64738), dport=port), verbose=False) #TODO: make sure that actually sends ACK, (manually if necessary)
                self.open_ports.append(port)
            else:
                logging.debug(f"TCP SYN attempt => FAILED => on {self.ip_str} port {port}")
        elif scan_type != "full":
            raise NotImplementedError(f"{scan_type} is not implemented yet")
        return len(result)
    
    def tcp_scan(self, scan_type, timeout=1) -> list:
        """
        TCP FULL SCAN : returns list of open-ports
        implemented scan types are:
        - full
        - half
        """
        threads = []
        for i in range(10, 23):
            threads.append(threading.Thread(target=self.tcp_single_probe, args=(i, scan_type), kwargs={"timeout" : 2}))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return self.open_ports

    def __str__(self) -> str:
        return self.ip_str


class Network:
    def __init__(self, ip: Ip) -> None:
        self.ip = ip
        self.host_list = []
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
        threads = []
        ip_iter = self.ip
        for i in range(0,self.get_nb_max_host()-2):
            threads.append(threading.Thread(target=self.__ping, args=(Ip(ip_iter.next(), ip_iter.netmask_str),)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return self.host_list
    
    def __ping(self, ip_iter):
        if ip_iter.ping(timeout=1):
            self.host_list.append(str(ip_iter))

if __name__ == "__main__":
    ip = Ip("10.132.65.106", "255.255.255.0")
    network = Network(ip)
    # host_list = network.ping_scan(1)
    # print(host_list)
    pckt = ip.tcp_scan("full")
    print(pckt)