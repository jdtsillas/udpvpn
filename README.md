### UDP VPN Tunnel

A simple program which sets up a cleartext IP tunnel between two endpoints using UDP.

Example:

```
$ sudo ./a.out --local=192.168.1.227:55555 --remote=192.168.1.228:55555
Remote: 192.168.1.228:55555
Local: 192.168.1.227:55555
Tunnel: tun1
```

To build on Linux:

```
g++ udpvpn.cpp -lboost_system -pthread -lboost_program_options
```

