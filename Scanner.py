from scapy.all import sr1, srp,IP,ICMP,Ether

class Ip:
    is_up = False
    def __init__(self, ip_str, netmask_str) -> None:
        self.ip_str = ip_str
        self.netmask_str = netmask_str
    
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

    def ping(self, ip: Ip) -> bool:
        pckt = Ether()/IP(dst=str(ip))/ICMP(type=8, code=0)
        print(pckt.show())
        pqt = sr1(pckt)
        return pqt
    
    def ping_scan(self) -> list:
        pass