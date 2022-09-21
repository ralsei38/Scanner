from array import array
import os
import sys
sys.path.append('scanner')
import model, controller, view
import pytest
import logging

#****** IP CLASS TEST ******#
def test_ip_init_wrong_ip_format():
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

def test_ip_init_port():
    ip = model.Ip("192.168.1.0", "255.255.255.0")
    ip.init_ports()
    coherent_state = True
    for port_state in ip.ports.values():
        if port_state != -1:
            coherent_state = False
            break
    assert(coherent_state == True)

def test_ip_init_wrong_ip_type():
    with pytest.raises(TypeError):
        model.Ip(14, "255.255.255.0") 
        model.Ip([], "255.255.255.0") 
        model.Ip({}, "255.255.255.0")

def test_ip_next():
    ip1 = model.Ip("192.168.1.0", "255.255.255.0")
    for i in range(0, 200):
        ip.next()
    assert(str(ip) == "192.168.1.200")

    ip2 = mode.Ip("192.168.1.0", "255.255.255.0")
    for i in range(0, 255+1):
        ip.next()
    assert(str(ip2) == "192.168.2.1")

def test_get_nb_max_host():
    net1 = model.Network(model.Ip("192.168.1.0", "255.255.255.0"))
    net2 = model.Network(model.Ip("192.168.1.0", "255.255.255.128"))
    assert(net1.get_nb_max_host() == (2**8-2))
    assert(net2.get_nb_max_host() == (2**7-2))

def test_ip_ping():
    ip1 = model.Ip("10.8.0.1", "255.255.255.0")
    ip3 = model.Ip("10.8.0.103", "255.255.255.0")
    ip4 = model.Ip("5.196.92.11", "255.255.255.0")
    ip1.ping_scan()
    ip3.ping_scan()
    ip4.ping_scan()
    assert(ip1.is_up[0] == True)
    assert(ip3.is_up[0] == True)
    assert(ip4.is_up[0] == True)

def test_ip_udp_csan():
    pass  # Dedicated VM 🧪 #31

def test_tcp_scan():
    pass  # Dedicated VM 🧪 #31

def test_network_ping_scan():
    ip = model.Ip("10.8.0.1", "255.255.255.0")
    network = model.Network(ip)
    network.ping_scan(1)
    assert(len(network.host_list) > 0)

def test_network_tcp_scan():
    ip = model.Ip("10.8.0.1", "255.255.255.0")
    with pytest.raises(NotImplementedError):
        print(ip.tcp_scan("other", 0.1))
        print(ip.tcp_scan("kek", 0.1))
        print(ip.tcp_scan("ful", 0.1))
    assert(len(ip.ports) > 0)

def test_network_udp_scan():
    ip = model.Ip("10.8.0.1", "255.255.255.0")
    ip.udp_scan()
    assert(len(ip.ports) > 0)