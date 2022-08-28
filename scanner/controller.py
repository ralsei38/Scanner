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
    except:
        continue

ip_str, netmask_str = view.ip_get()

if FOCUS_LIST[key_focus] == "ip scan":
    entity = Ip(ip_str, netmask_str)
elif FOCUS_LIST[key_focus] == "network scan":
    entity = Network(Ip(ip_str, netmask_str))
else:
    print("unexpected focus")

if ACTION_LIST[key_action] == "ping scan":
    print(entity.ping_scan())
if ACTION_LIST[key_action] == "tcp scan: full":
    print(entity.tcp_scan())