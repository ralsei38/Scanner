from array import array
import os
import sys
sys.path.append('scanner')
import model, controller, view
import pytest
import logging



# TEST IP CLASS
def test_init_wrong_ip_format():
    with pytest.raises(ValueError):
        model.Ip("192.168.1.0.0", "255.255.255.0")
    with pytest.raises(ValueError):
        model.Ip("192.168.1.0", "255.255.255.0.0")
    with pytest.raises(ValueError):
        model.Ip("192..168.1.0", "255.255.255..0")
    with pytest.raises(ValueError):
        model.Ip("1some4", "255.255.255.0")
    with pytest.raises(ValueError):
        model.Ip("a.a.a.b", "255.255.255..0")

def test_init_wrong_ip_type():
    with pytest.raises(TypeError):
        model.Ip(14, "255.255.255.0") 
        model.Ip([], "255.255.255.0") 
        model.Ip({}, "255.255.255.0")

def test_get_nb_max_host():
    net1 = model.Network(model.Ip("192.168.1.0", "255.255.255.0"))
    net2 = model.Network(model.Ip("192.168.1.0", "255.255.255.128"))
    assert(net1.get_nb_max_host() == (2**8-2))
    assert(net2.get_nb_max_host() == (2**7-2))

def test_ping(): #cannot be tested using Continuous Integration
    """
        cannot be tested using continous integration
    """
    #manually tested
    assert(model.Ip("10.8.0.1", "255.255.255.0").ping_scan() == True)
    assert(model.Ip("10.8.0.102", "255.255.255.0").ping_scan() == True)
    assert(model.Ip("10.8.0.103", "255.255.255.0").ping_scan() == False)
    assert(model.Ip("5.196.92.11", "255.255.255.0").ping_scan() == True)

def test_ping_scan():
    ip = model.Ip("10.8.0.1", "255.255.255.0")
    network = model.Network(ip)
    host_list = network.ping_scan(1)
    assert(isinstance(host_list, list))

def test_tcp_scan(): #cannot be tested using Continuous Integration
    ip = model.Ip("10.8.0.1", "255.255.255.0")
    with pytest.raises(NotImplementedError):
        print(ip.tcp_scan("other", 0.1))
        print(ip.tcp_scan("kek", 0.1))
        print(ip.tcp_scan("ful", 0.1))
    assert(isinstance(ip.tcp_scan("full", 0.1), list))

def test_udp_scan(): #cannot be tested using Continuous Integration
    ip = model.Ip("192.168.1.1", "255.255.255.0")
    assert(isinstance(ip.udp_scan(1), list))