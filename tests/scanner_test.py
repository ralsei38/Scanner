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

def test_idiotic():
    """
    just making sure that CI will spot bad coverage
    """
    assert(scanner.Ip("192.168.1.0", "255.255.255.0") == scanner.Ip("192.168.1.0", "255.255.255.0"))
# def test_ping():
#     assert(scanner.Network(scanner.Ip("192.168.1.0", "255.255.255.0")).ping(scanner.Ip("192.168.1.13", "255.255.255.0")))