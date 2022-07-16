import os
import sys
sys.path.append('scanner')
import scanner
import pytest


# TEST IP CLASS
def test_init():
    ip = scanner.Ip("192.168.1.0", "255.255.255.0")
    assert(str(ip) == "192.168.1.0")