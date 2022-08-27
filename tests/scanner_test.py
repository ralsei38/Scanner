from array import array
import os
import sys
sys.path.append('scanner')
import scanner
import pytest


# TEST IP CLASS
def test_init_wrong_ip_format():
    with pytest.raises(ValueError):
        scanner.Ip("192.168.1.0.0", "255.255.255.0")
    with pytest.raises(ValueError):
        scanner.Ip("192.168.1.0", "255.255.255.0.0")
    with pytest.raises(ValueError):
        scanner.Ip("192..168.1.0", "255.255.255..0")
    with pytest.raises(ValueError):
        scanner.Ip("1some4", "255.255.255.0")
    with pytest.raises(ValueError):
        scanner.Ip("a.a.a.b", "255.255.255..0")

def test_init_wrong_ip_type():
    with pytest.raises(TypeError):
        scanner.Ip(14, "255.255.255.0") 
        scanner.Ip([], "255.255.255.0") 
        scanner.Ip({}, "255.255.255.0")

def ping(): #cannot be tested using Continuous Integration
    """
        cannot be tested using continous integration
    """
    #manually tested
    assert(scanner.Ip("192.168.1.0", "255.255.255.0").ping() == False)
    assert(scanner.Ip("192.168.1.1", "255.255.255.0").ping() == True)

def ping_scan():
    #manually tested
    ip = scanner.Ip("127.0.0.1", "255.255.255.252")
    network = scanner.Network(ip)
    host_list = network.ping_scan(1)

def test_tcp_scan(): #cannot be tested using Continuous Integration
    with pytest.raises(NotImplementedError):
        ip = scanner.Ip("127.0.0.1", "255.255.255.0")
        ip.tcp_scan("half", 5)