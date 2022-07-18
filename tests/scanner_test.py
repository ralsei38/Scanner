from array import array
import os
import sys

from scanner.scanner import Network
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

def test_ping():
    assert(scanner.Network(scanner.Ip("192.168.1.0", "255.255.255.0")).ping("192.168.1.0"))

def test_ping_scan():
    ip = scanner.Ip("192.168.1.0", "255.255.255.0")
    network = Network(ip)
    result = network.ping_scan() 
    assert(isinstance(result, array()))
    assert("192.168.1.0" in result)