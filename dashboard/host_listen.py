#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Portas TCP em LISTEN e interfaces do HOST.

Executado pelo Radar dentro de um container efêmero lançado com
`docker run --rm --network host` (o HomeHub já tem acesso ao docker.sock).
Imprime JSON: {"listeners": [{"port": 5000, "addrs": ["0.0.0.0"]}, ...],
               "interfaces": {"enp1s0": "10.11.2.145", ...}}
"""
import fcntl
import json
import socket
import struct


def _fmt_addr(hexaddr):
    try:
        if len(hexaddr) == 8:                       # IPv4 (little-endian)
            return socket.inet_ntoa(bytes.fromhex(hexaddr)[::-1])
        if len(hexaddr) == 32:                      # IPv6 (grupos little-endian)
            raw = b"".join(bytes.fromhex(hexaddr[i:i + 8])[::-1]
                           for i in range(0, 32, 8))
            try:
                return socket.inet_ntop(socket.AF_INET6, raw)
            except OSError:
                return raw.hex()
    except Exception:
        pass
    return hexaddr


def _interfaces():
    """IPv4 de cada interface (SIOCGIFADDR por interface, via /proc/net/dev)."""
    out = {}
    try:
        with open("/proc/net/dev") as f:
            lines = f.read().splitlines()[2:]
    except OSError:
        return out
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for line in lines:
            name = line.split(":", 1)[0].strip()
            if not name or len(name) >= 16:
                continue
            req = bytearray(40)                      # ifreq: nome[16] + sockaddr
            nb = name.encode()
            req[:len(nb)] = nb
            try:
                fcntl.ioctl(s.fileno(), 0x8915, req, True)   # SIOCGIFADDR
            except OSError:
                continue
            family = struct.unpack("H", bytes(req[16:18]))[0]
            if family != socket.AF_INET:
                continue
            out[name] = socket.inet_ntoa(bytes(req[20:24]))
        return out
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    listeners = {}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = open(path).read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":   # 0A = LISTEN
                continue
            addr_hex, _, port_hex = parts[1].rpartition(":")
            try:
                port = int(port_hex, 16)
            except ValueError:
                continue
            entry = listeners.setdefault(port, {"port": port, "addrs": set()})
            entry["addrs"].add(_fmt_addr(addr_hex))
    print(json.dumps({
        "listeners": [{"port": p, "addrs": sorted(v["addrs"])}
                      for p, v in sorted(listeners.items())],
        "interfaces": _interfaces(),
    }))


if __name__ == "__main__":
    main()
