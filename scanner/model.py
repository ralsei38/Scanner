import pdb
import random
import sys
import threading
from time import sleep
import logging
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(level=logging.ERROR)

FOCUS_LIST = {
    1 : 'network scan',
    2 : 'ip scan',
}

ACTION_LIST = {
    1 : 'ping scan',
    2 : 'tcp scan: full',
}


class Ip:
    def __init__(self, ip_str: str, netmask_str: str) -> None:
        if not isinstance(ip_str, str) or not isinstance(netmask_str, str):
            raise TypeError
        if len(ip_str.split('.')) != 4 or len(netmask_str.split('.')) != 4:
            raise ValueError
        
        self.ip_str = ip_str
        self.netmask_str = netmask_str

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
        return self.ip_str #used for threading

    def ping_scan(self, timeout=1) -> bool:
        pkt = IP(dst=self.ip_str)/ICMP(type=8, code=0)
        return sr1(pkt, timeout=timeout, verbose=False) is not None

    def __tcp_port_scan(self, port, open_ports, scan_type="full", timeout=5) -> None:
        """
        Procedure appending a port to a list if responding to TCP probe
        This method is called by the "tcp_scan" method.
        """
        pkt = IP(dst=self.ip_str)/TCP(flags='S', dport=port)
        result, _ = sr(pkt, timeout=2, verbose=False)
        if "full" in scan_type:
            if len(result):
                open_ports.append(port)
                logging.debug(f"TCP SYN attempt => SUCESSFULL => on {self.ip_str} port {port}")
                logging.debug(f"sending TCP ACK attempt on {self.ip_str} port {port}")
                send(Ether()/IP(dst=self.ip_str)/TCP(sport=random.randrange(49152, 64738), dport=port), verbose=False) #TODO: make sure that actually sends ACK, (manually if necessary)
        else:
            raise NotImplementedError(f"{scan_type} is not implemented yet")
        
    
    def tcp_scan(self, scan_type="full", timeout=5) -> list:
        """
        TCP FULL SCAN : returns list of open-ports
        This method calls the "__tcp_port_scan" method
        implemented scan types are:
        - full
        """
        threads = []
        open_ports = []
        for i in range(50, 200):
            threads.append(threading.Thread(target=self.__tcp_port_scan, args=(i, open_ports, scan_type, timeout)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return open_ports
    
    
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
        return 2 ** n_free_bits - 1 # last IP broadcast, real number is 2 ** nb_free_bits - 2 

    def ping_scan(self, timeout=1) -> list:
        host_list = []
        threads = []
        open_ports = []
        ip_iter = self.ip
        
        for i in range(0,self.get_nb_max_host()-2):
            threads.append(threading.Thread(target=self.__ping, args=(Ip(ip_iter.next(), ip_iter.netmask_str), host_list)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return host_list

    def __ping(self, ip_iter, host_list) -> None:
        """
        Procedure appending a host to a list if responding to ICMP probe
        """
        if ip_iter.ping_scan(timeout=1):
            host_list.append(str(ip_iter))

    def tcp_scan(self, scan_type="full", timeout=5) -> list:
        raise NotImplementedError("network tcp scan not implemented yet !")