#!/usr/bin/env python3
"Temporary diagnostic: which UDP sends does this host allow?"
import itertools
import os
import platform
import socket
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import psl_class  # noqa: E402

print(platform.platform())
iface = psl_class.default_interface()
ip = psl_class.get_ip_address(iface)
print(iface, ip)
if sys.platform == "darwin":
    print(subprocess.run(["netstat", "-rn", "-f", "inet"], capture_output=True, text=True).stdout)
    print(subprocess.run(["ifconfig", iface], capture_output=True, text=True).stdout)
subnet_bc = ".".join(ip.split(".")[:3] + ["255"])
gw = ".".join(ip.split(".")[:3] + ["1"])
for bind_ip, bound_if, dest in itertools.product(
        [None, ip, ""], [False, True],
        ["255.255.255.255", subnet_bc, gw, ip, "127.0.0.1"]):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        if bind_ip is not None:
            s.bind((bind_ip, 0))
        if bound_if:
            s.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_BOUND_IF", 25),
                         socket.if_nametoindex(iface))
        s.sendto(b"x", (dest, 63322))
        res = "ok"
    except OSError as e:
        res = "ERR %s" % e
    print("bind=%-14r bound_if=%-5s dest=%-16s %s" % (bind_ip, bound_if, dest, res))
    s.close()
