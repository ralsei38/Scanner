from pyfiglet import Figlet
import os

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
        