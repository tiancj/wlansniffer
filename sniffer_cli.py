#!/home/tiancj/python/py3k/bin/python

import socket
import os
import sys
import eloop

CTRL_IFACE = '/tmp/sniffer.sock'


def main():
    if not os.path.exists(CTRL_IFACE):
        print("CTRL_IFACE not exist")
        return

    client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    client.connect(CTRL_IFACE)
    print("Ready")
    while True:
        try:
            x = input(">")
            if x:
                client.send(x.encode('utf8'))
        except KeyboardInterrupt as e:
            print("shutdown...")
    client.close()


if __name__ == '__main__':
    main()