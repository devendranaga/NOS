#!/bin/bash
#
## Run Logger Daemon in normal mode with file.
./logger/nos_logger -t 1 -i 127.0.0.1 -P 1441 -p log -r 10240000 &

## Run the Firewall service
sudo ./firewall/nos_firewall -f firewall_config.json&
