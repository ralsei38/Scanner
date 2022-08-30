from model import Ip, Network, ACTION_LIST, FOCUS_LIST
from view import View

view = View()
view.welcome()
key_focus = None
key_action = None

while True:
    try:
        key_focus = int(view.list_focus(FOCUS_LIST))
        if key_focus not in FOCUS_LIST:
            continue
        key_action = int(view.list_actions(ACTION_LIST))
        if key_action not in ACTION_LIST:
            continue
        break
    except ValueError:
        print("wrong input, ...")
        print("-"*5)
        continue

while True:
    try:
        ip_str, netmask_str = view.ip_get()
        Ip(ip_str,netmask_str)
        break
    except (TypeError, ValueError):
        print("wrong input")
        print("-"*5)
        continue
if FOCUS_LIST[key_focus] == "ip scan":
    entity = Ip(ip_str, netmask_str)
elif FOCUS_LIST[key_focus] == "network scan":
    entity = Network(Ip(ip_str, netmask_str))
else:
    print("unexpected focus")

if ACTION_LIST[key_action] == "ping scan":
    print(entity.ping_scan(timeout=2))
if ACTION_LIST[key_action] == "TCP scan: full":
    print(entity.tcp_scan("full", timeout=5))
if ACTION_LIST[key_action] == "TCP scan: half":
    print(entity.tcp_scan("half", timeout=5))
if ACTION_LIST[key_action] == "UDP scan":
    print(entity.udp_scan(timeout=5))