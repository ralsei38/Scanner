import pdb
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
    def __init__(self, ip) -> None:
        self.ip = ip
        # self.nb_host = self.get_nb_host()
    
    def ping(self, ip: Ip) -> bool:
        pckt = Ether()/IP(dst=str(ip))/ICMP(type=8, code=0)
        pqt = sr1(pckt)
        return pqt
    
    def get_nb_host_support(self) -> int:
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
        '''
        255.255.255.0
        1111 1111. 1111 1111. 1111 1111. 0000 0000
        '''
        pass