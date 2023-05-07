# NOS (Network OS) Middleware

Network OS Middleware is aimed at achieving the following:

1. Provide a common core library to achieve reusable software components.
2. Provide Cryptography capabilities extensively independent of underlying interface.
3. Provide Software download capabilities independent of underlying Flavor (OpenWRT/Yocto etc).
4. Provide Firewall capabilities for detection and prevention (Most important aspect of this project).
5. Provide Logging and Debugging capabilities of all the services.
6. Manage all the above services either via service manager or via systemd scripts.

To achieve this the code is organized as follows.

1. lib/core/ -> for core reusable components.
2. lib/crypto/ -> for underlying crypto library implementation independent functionality.
3. services/firewall -> firewall service
4. services/logger -> logger service

