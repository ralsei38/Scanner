import pdb
import sys
from threading import Thread, Lock
from time import sleep
import logging
from scapy.all import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(level=logging.ERROR) #DEBUG ERROR

FOCUS_LIST = {
    1 : 'network scan',
    2 : 'ip scan',
}

ACTION_LIST = {
    1 : 'PING scan',
    2 : 'TCP scan: full',
    3 : 'TCP scan: half',
    4 : 'UDP scan',
}

SCAN_TYPES = ["full", "half"]

class Ip:
    def __init__(self, ip_str: str, netmask_str: str) -> None:
        self._ip_str = ip_str
        self._netmask_str = netmask_str
        self.ports = {
            # key : value <=> port_number : state
            # state {=> -1, 0, 1
        }
        self.init_ports()
        self.is_up = (False, str(datetime.now()).split(' ')[-1])
    
    @property
    def ip_str(self):
        return self._ip_str

    @property
    def netmask_str(self):
        return self._netmask_str

    @ip_str.setter
    def ip_str(self, ip_str):
        if not isinstance(ip_str, str):
            raise TypeError
        self.ip_str = ip_str
  
    @netmask_str.setter
    def netmask_str(self, netmask_str):
        if not isinstance(netmask_str, str):
            raise TypeError
        self.netmask_str = netmask_str

    def init_ports(self) -> None:
        for port in range(0, 1025):
            """
            ports is a dictionnary
            key : value <=> port_number : port_state
            port_state can be either -1 (unscanned), 0 (closed) and 1 (opened)
            """
            self.ports[str(port)] = -1

    def next(self) -> str:
        """
        affects the next local IP to the ip_str variable
        """
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

    def ping_scan(self, timeout=1) -> None:
        """
        sending an ICMP packet, spoofing will soon be implemented
        """
        pkt = IP(dst=self.ip_str)/ICMP(type=8, code=0)
        response = sr1(pkt, timeout=timeout, verbose=False)
        if response is not None and response.type != 3:
            self.is_up = (True, str(datetime.now()).split(' ')[-1])
        else:
            self.is_up = (False, str(datetime.now()).split(' ')[-1])

    
    def udp_scan(self, timeout=1) -> None:
        threads = []
        self.ports = []
        current_ports = [i for i in range(0, 1025)]
        for i in range(1, 400):
            threads.append(threading.Thread(target=self.__udp_port_scan, args=(current_ports, timeout)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __udp_port_scan(self, current_ports, timeout=5) -> None:
        """
        Procedure appending a port to a list if responding to TCP probe
        This method is called by the "tcp_scan" method.
        """
        while len(current_ports) > 0:
            mutex = Lock()
            try:
                mutex.acquire()
                port = current_ports.pop()
            finally:
                mutex.release()
            pkt = IP(dst=self.ip_str)/UDP(dport=port)
            response, _ = sr(pkt, timeout=timeout, verbose=False)
            if len(response):
                logging.debug(f"UDP response => OK {self.ip_str} port {port}")
                self.ports.append(port)
                self.is_up = True, str(datetime.now()).split(' ')[-1]
            else:
                logging.debug(f"UDP response => FAIL {self.ip_str} port {port}")

    def tcp_scan(self, scan_type="full", timeout=1) -> None:
        f"""
        TCP FULL SCAN : returns list of open-ports
        This method calls the "__tcp_port_scan" method
        implemented scan types are: {SCAN_TYPES}
        """
        
        if scan_type not in SCAN_TYPES:
            raise NotImplementedError
        
        threads = []
        self.ports = []
        current_ports = [i for i in range(0, 1025)]
        for i in range(1, 200):
            threads.append(threading.Thread(target=self.__tcp_port_scan, args=(current_ports, scan_type, 1.5)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __tcp_port_scan(self, current_ports: dict, scan_type="full", timeout=1) -> None:
        """
        Procedure appending a port to a list if responding to TCP probe
        This method is called by the "tcp_scan" method.
        """
        while len(current_ports) > 0:
            
            #picking a port from the port list
            mutex = Lock()
            mutex.acquire()
            port = ""
            try:
                port = current_ports.pop()
            finally:
                mutex.release()
            #scanning it
            pkt_syn = IP(dst=self.ip_str)/TCP(flags='S', dport=port, seq=1000)
            pkt_conn_start, _ = sr(pkt_syn, timeout=timeout, verbose=False)

            #Excuse the mess...
            if "full" in scan_type: #TCP full scan
                if len(pkt_conn_start):
                    self.ports.append(port)
                    logging.debug(f"TCP SYN attempt => SUCESSFULL => on {self.ip_str} port {port}")
                    logging.debug(f"sending TCP ACK attempt on {self.ip_str} port {port}")
                    pkt_conn_end = IP(dst=self.ip_str)/TCP(flags='RA', dport=port, seq=pkt_syn.ack, ack=pkt_syn.seq+1)
                    send(pkt_conn_end, verbose=False)
                    self.is_up = True, str(datetime.now()).split(' ')[-1]
                else:
                    logging.debug(f"TCP SYN attempt => FAILED => on {self.ip_str} port {port}")

            elif "half" in scan_type: #TCP half-open scan
                if len(pkt_conn_start):
                    self.ports.append(port)
                    logging.debug(f"TCP SYN attempt => SUCESSFULL => on {self.ip_str} port {port}")
                else:
                    logging.debug(f"TCP SYN attempt => FAILD => on {self.ip_str} port {port}")
            else:
                self.ports.append(port)
                raise NotImplementedError(f"{scan_type} is not implemented yet")
    def __str__(self) -> str:
        return self.ip_str


class Network:
    def __init__(self, ip: Ip) -> None:
        self.ip = ip
        self.host_list = []
    
    
    def get_nb_max_host(self) -> int:
        """
            How much hosts can this ip range welcome
        """
        netmask_bin = ''.join([ format(int(part), '08b') for part in self.ip.netmask_str.split('.')])
        n_free_bits = 0
        for i in reversed(netmask_bin):
            if int(i) == 0:
                n_free_bits += 1
            else:
                break
        return 2 ** n_free_bits - 2

    def host_list_init(self) -> list:
        ip_iter = self.ip
        host_list = [Ip(ip_iter.next(),ip_iter.netmask_str) for i in range(self.get_nb_max_host() - 2)]
        host_list.append(self.ip)
        return host_list
    
    def ping_scan(self, timeout=2) -> None:
        threads = []
        self.host_list = []
        host_list = self.host_list_init()

        for i in range(100):
            threads.append(threading.Thread(target=self.__ping, args=(host_list, timeout)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __ping(self, host_list, timeout=1) -> None:
        """
        Procedure appending a host to a list if responding to ICMP probe
        """
        while len(host_list) > 0:
            mutex = Lock()
            try:
                mutex.acquire()
                current_ip = host_list.pop()
            finally:
                mutex.release()
            current_ip.ping_scan(timeout=timeout)

            if current_ip.is_up[0]:
                self.host_list.append(current_ip)
                logging.debug(f"thread {self} scanning: {current_ip} => SUCCESS")
            else:
                logging.debug(f"thread {self} scanning: {current_ip} => FAILURE")

    def tcp_scan(self, scan_type="full", timeout=1) -> None:
        
        if scan_type not in SCAN_TYPES:
            raise NotImplementedError(f"scan type {scan_type} not implemented yet tcp scan not implemented yet")
        threads = []
        self.host_list = []
        self.ping_scan()
        host_list = self.host_list.copy()
        
        for i in range(2):
            threads.append(threading.Thread(target=self.__tcp_scan, args=(host_list, scan_type, timeout)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def __tcp_scan(self, host_list, scan_type="full", timeout=1) -> None:
        while len(host_list) > 0:
            mutex = Lock()
            try:
                mutex.acquire()
                ip = host_list.pop()
            finally:
                mutex.release()

            ip.tcp_scan(scan_type)
            self.host_list.append(ip)

    def udp_scan(self, timeout=1) -> None:
            threads = []
            self.host_list = []
            host_list = []
            raise NotImplementedError("network tcp scan not implemented yet !")
    
    def arp_scan(self):
        raise NotImplementedError

    def dhcp_spoofing(self, stealth: bool):
        """
        a simple dhcp spoofing method,
        exthausion makes dhcp way more efficient.
        """
        if stealth:
            dhco
        if dhcp_server is not None:
            pass
        pass
    
    def __str__(self) -> str:
        return str(self.ip)