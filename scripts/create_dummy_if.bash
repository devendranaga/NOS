#!/bin/bash

modprobe dummy
ip link add dummy0 type dummy
ip link set dummy0 up
ip link add dummy1 type dummy
ip link set dummy1 up

