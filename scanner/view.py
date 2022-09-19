from pyfiglet import Figlet
import os
from model import Ip, Network, ACTION_LIST, FOCUS_LIST

class View():
    def __init__(self):
        self.f = Figlet()
    
    def welcome(self):
        os.system('cls||clear')
        print(self.f.renderText('ScapyScanner'))
    
    def list_focus(self, focus: dict) -> int:
        user_focus = None
        
        for key in focus:
            print(key, '->', focus[key])
        user_focus = input()
        return user_focus
    
    def list_actions(self, actions: dict) -> int:
        user_action = None
        
        for key in actions:
            print(key, '->', actions[key])
        user_action = input()
        return user_action
    
    def ip_get(self):
        ip_str = input("ip: ")
        netmask_str = input("netmask: ")
        return (ip_str, netmask_str)
    
    def summary(self, entity) -> None:
        if isinstance(entity, Network):
            print(f"address: {entity}")
            print(f"hosts: {[str(host) for host in entity.host_list]}")
            print("HOSTS:\n")
            for host in entity.host_list:
                print(f"host: {host}")
                print(f"up: {host.is_up[0]}, scan timestamp: {host.is_up[1]}")
        elif isinstance(entity, Ip):
            print(f"address: {entity}")
            print(f"is up: {entity.is_up[0]}")
            print(f"scan timestamp: {entity.is_up[1]}")
        else:
            raise TypeError