#!/usr/bin/python3

#script that creates and enables the interfaces

import os

interfaces = ["dummy0", "dummy1"]

for interface in interfaces:
    os.system("sudo ip link add " + interface + " type dummy")
    os.system("sudo ifconfig " + interface + " up")

