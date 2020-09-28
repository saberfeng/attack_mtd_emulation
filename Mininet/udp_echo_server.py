#!/usr/bin/python2.7
"""
udp_echo_server.py
A simple echo server. Intended to be run on hosts in a Mininet testbed to open ports that can be detected by an
Nmap UDP (-sU) scan.
"""

import socket
from select import select
import sys


class EchoServer(object):
    def __init__(self, server_port):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if not (0 <= server_port <= 65535):
                raise ValueError("Incorrect port range")
            self.server_sock.bind(('', server_port))
        except ValueError as error:
            print(error)
            sys.exit()
        except OSError as error:
            print(error)
            self.server_sock.close()
            sys.exit()
        self.run()

    def run(self):
        try:
            while True:
                read_sockets, _, _ = select([self.server_sock], [], [])
                if len(read_sockets) != 0:
                    print("*** Input at socket ***")
                    self.echo()
        finally:
            self.server_sock.close()

    def echo(self):
        data, inet_addr = self.server_sock.recvfrom(512)
        self.server_sock.sendto(data, inet_addr)
        return


if __name__ == '__main__':
    EchoServer(5678)
	
