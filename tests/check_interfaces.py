#!/usr/bin/env python3
"Compare psl_class interface detection with what the OS tools report"
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import psl_class  # noqa: E402

iface = psl_class.default_interface()
print("default interface:", iface)
assert iface, "no default interface found"
mac = psl_class.get_hw_addr(iface)
ip = psl_class.get_ip_address(iface)
print("mac:", mac, "ip:", ip)

if sys.platform.startswith("linux"):
    with open("/sys/class/net/%s/address" % iface) as f:
        expected_mac = f.read().strip()
    out = subprocess.run(["ip", "-4", "-o", "addr", "show", iface],
                         capture_output=True, text=True).stdout
else:
    out = subprocess.run(["ifconfig", iface],
                         capture_output=True, text=True).stdout
    expected_mac = re.search(r"ether ([0-9a-f:]+)", out).group(1)
expected_ips = re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out)
print("expected mac:", expected_mac, "ips:", expected_ips)
assert mac == expected_mac, "mac mismatch"
assert ip in expected_ips, "ip mismatch"
print("OK")
