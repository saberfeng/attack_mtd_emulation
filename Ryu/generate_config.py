#!/usr/bin/python2.7
"""
generate_config.py
Generates a config file, in JSON, used by the Mininet network and Ryu controllers.
"""
__author__ = "Cole Dishington"
__email__ = "cole.dishington@pg.canterbury.ac.nz"
__status__ = "Development"

from random import SystemRandom  # cryptographically secure random number generator as implemented by OS
import sys
import json

generator = SystemRandom()


def gen_ports(port_range, num_ports):
    """
    Generates Random ports within a range.
    :param List[int] port_range: Range of ports, specified by tuple or list.
    :param int num_ports: Number of ports to be generated in the range.
    :return List[int]: Generated ports.
    """
    return generator.sample(port_range, num_ports)


def parse_input():
    """
    Parses input specified on the commandline, order is important (haven't added tags).
    :return: Parsed and validated input
    """

    params = sys.argv[1:]
    if len(params) != 9:
        print("Need all params")
        sys.exit()

    try:
        num_hosts = int(params[0])
    except ValueError as err:
        print("Error in param 1: {}".format(err))
        sys.exit()

    try:
        num_ports = int(params[1])
    except ValueError as err:
        print("Error in param 2: {}".format(err))
        sys.exit()

    try:
        port_list = map(int, params[2].split("-"))
        if len(port_list) != 2:
            print("Port range incorrect")
            sys.exit()
    except ValueError as err:
        print("Error in param 3: {}".format(err))
        sys.exit()

    try:
        mtd_time = int(params[3])
    except ValueError as err:
        print("Error in param 4: {}".format(err))
        sys.exit()

    try:
        controller_type = str(params[4])
        if controller_type not in ("FRVM", "tSDN", "RSM"):
            raise ValueError("Incorrect controller type")
    except ValueError as err:
        print("Error in param 5: {}".format(err))
        sys.exit()

    try:
        scan_type = str(params[5])
        if scan_type not in ("sS", "sT", "sN", "sX", "sF", "sU"):
            raise ValueError("Incorrect scan type")
    except ValueError as err:
        print("Error in param 6: {}".format(err))
        sys.exit()

    # Prior port knowledge
    try:
        temp = str(params[6])
        if temp not in ("0", "1", "false", "true"):
            raise ValueError("Ports discovered not boolean")
        else:
            ports_discovered = temp in ("1", "true")
    except ValueError as err:
        print("Error in param 7: {}".format(err))
        sys.exit()

    # Scanning for single port
    try:
        temp = str(params[7])
        if temp not in ("0", "1", "false", "true"):
            raise ValueError("Single port not boolean")
        else:
            single_port = temp in ("1", "true")
    except ValueError as err:
        print("Error in param 7: {}".format(err))
        sys.exit()

    # MTD interval scan
    try:
        mtd_interval_scan = int(params[8])
        if mtd_interval_scan:
            mtd_time = 2**16 - 1
    except ValueError as err:
        print("Error in param 8: {}".format(err))
        sys.exit()

    return num_hosts, num_ports, range(port_list[0], port_list[1]), mtd_time, controller_type, scan_type, \
           ports_discovered, single_port, mtd_interval_scan


def create_json():
    num_hosts, num_ports, port_range, mtd_time, controller_type, scan_type, ports_discovered, single_port, mtd_interval_scan = parse_input()
    data = {"num_ports": num_ports,
            "num_hosts": num_hosts,
            "mtd_time": mtd_time,
            "controller_type": controller_type,
            "scan_type": scan_type,
            "ports_discovered": ports_discovered,
            "single_port": single_port,
            "MTD_interval_scan": mtd_interval_scan}

    for host in range(num_hosts):
        ports = gen_ports(port_range, num_ports)
        data[host] = ports

    return json.dumps(data, separators=(',', ':'), indent=4)


if __name__ == '__main__':
    json_object = create_json()
    file = open("./Ryu/hosts_ports.json", 'w')
    file.write(json_object)
    file.close()
