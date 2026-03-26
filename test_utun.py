#!/usr/bin/env python3
import socket, struct, fcntl
AF_SYSTEM = 32
AF_SYS_CONTROL = 2
SYSPROTO_CONTROL = 2
CTLIOCGINFO = 0xC0644E03

try:
    s = socket.socket(AF_SYSTEM, socket.SOCK_DGRAM, SYSPROTO_CONTROL)
    print("socket(AF_SYSTEM) OK, fd =", s.fileno())
    name = b"com.apple.net.utun_control\x00"
    info = struct.pack("I96s", 0, name.ljust(96, b"\x00"))
    result = fcntl.ioctl(s.fileno(), CTLIOCGINFO, info)
    ctl_id = struct.unpack("I96s", result)[0]
    print("CTLIOCGINFO OK, ctl_id =", ctl_id)
    s.close()
    for unit in range(0, 16):
        s2 = socket.socket(AF_SYSTEM, socket.SOCK_DGRAM, SYSPROTO_CONTROL)
        try:
            s2.connect((ctl_id, unit+1))
            print("utun%d: CREATED (fd=%d)" % (unit, s2.fileno()))
            s2.close()
            break
        except Exception as e:
            print("utun%d: %s" % (unit, e))
            s2.close()
except Exception as e:
    print("FAILED:", type(e).__name__, e)
