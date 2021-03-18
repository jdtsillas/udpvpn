### UDP VPN Tunnel

A simple program which sets up a cleartext (or optionally encrypted) IP tunnel between endpoints using UDP.

Example:

```
$ sudo ./a.out --local=192.168.1.227:55555 --remote=192.168.1.228:55555
Remote: 192.168.1.228:55555
Local: 192.168.1.227:55555
Tunnel: tun1
```

To build on Linux:

```
g++ udpvpn.cpp -lboost_system -pthread -lboost_program_options -lcrypto
```

## Optional Features

Option              | Description
=================== | ==========
--tunnel=name       | Use "name" for the device when creating or binding to a tunnel.
--key=key_file_path | Use "key_file_path" to load a private symmetric key for encryption. The file will contain a 256 bit key and a 128 bit initial vector. The same key file would be used on all connected endpoints. The file should be generated using openssl.

```
$ openssl rand 48 > sym_keyfile.key
```

