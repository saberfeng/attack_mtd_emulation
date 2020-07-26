#!/usr/bin/python2.7
"""
open_ports.py
Opens a server on either random or specified ports.
"""

from random import SystemRandom  # cryptographically secure random number generator as implemented by OS
import SimpleHTTPServer
import SocketServer
import threading
import sys
from udp_echo_server import EchoServer


def open_udp_server(ports):
    """
    Open UDP echo servers on the specified ports.
    :param ports: List of ports.
    :return: None
    """
    for port in ports:
        print("Serving at port", port)
        threading.Thread(target=EchoServer, name=str(port), args=(port,)).start()


def open_http_server(ports):
    """
    Open HTTP servers on specified ports.
    :param ports: List of ports
    :return: None
    """
    for port in ports:
        Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
        httpd = SocketServer.TCPServer(("", port), Handler)

        print("Serving at port", port)
        threading.Thread(target=httpd.serve_forever, name=str(port)).start()


def gen_ports():
    """
    Generate a list of random ports.
    :return: None
    """
    generator = SystemRandom()
    return generator.sample(range(50000, 51000), 10)


def input_handler():
    """
    Handle commandline input specifying the type of server, and optionally a list of ports.
    :return: Handle to server with ports and ports.
    """
    input_params = sys.argv[1:]
    if len(input_params) < 1:
        sys.exit()
    if sys.argv[1] == "tcp":
        service_handler = open_http_server
    elif sys.argv[1] == "udp":
        service_handler = open_udp_server
    else:
        sys.exit()

    if len(input_params) > 1:
        ports = map(int, input_params[1:])
    else:
        ports = gen_ports()
    return service_handler, ports


if __name__ == '__main__':
    service_handler, ports = input_handler()
    service_handler(ports)
