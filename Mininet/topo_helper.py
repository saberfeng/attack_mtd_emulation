"""
topo_helper.py
Contains various helpful functions for aiding the configuration in Mininet networks.
"""

import re


def open_host_ports(net, config, protocol="tcp"):
    """
    Opens ports, specified in config, on each host specified in net (with a name beginning with h)
    :param net: Mininet net object
    :param config: A configuration file containing the ports of hosts to open.
    :param protocol: The protocol to offer over the port.
    :return: None
    """
    nodes = net.hosts
    for idx in range(len(nodes)):
        node = nodes[idx]
        if re.match(r'h\d+', node.name):
            ports = config.get(str(idx), None)
            print("Host {} opening ports {}", idx, " ".join(map(str, ports)))
            # ./Mininet/open_ports.py tcp 1111 2222 3333 &
            command = "./Mininet/open_ports.py {} {} &".format(protocol, " ".join(map(str, ports)))
            node.cmd(command)


def open_rnd_host_ports(net, protocol="tcp"):
    """
    Opens random ports on each host specified in net (with a name beginning with h)
    :param net: Mininet net object
    :param protocol: The protocol to offer over the port.
    :return: None
    """
    run_commands(net.hosts, ["./Mininet/open_ports.py {} &".format(protocol)], lambda x: re.match(r'h\d+', x.name))


def configure_router(r1, subnets):
    """
    Configure router with interfaces in different subnets and IP forwarding.
    :param r1: Mininet Host object representing a router.
    :param subnets: List of IP addresses
    :return: None
    """
    # Adding interfaces
    for i in range(0, len(subnets)):
        r1.cmd("ifconfig r1-eth{0} {1}".format(i, subnets[i]))
        r1.cmd("ifconfig r1-eth{0} hw ether 00:00:00:00:01:0{0}".format(i))

    # Configuring network services
    r1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")


def add_default_route(net, ip):
    """
    Add default route to specified address for all Mininet hosts with names beginning with 'h'.
    :param net: Mininet network object
    :param ip: Default route IP address
    :return: None
    """
    print("--- Adding default routes ---")
    run_commands(net.hosts, ["ip route add default via {0}".format(ip)], lambda x: re.match(r'h\d+', x.name))


def run_dhclient_on_hosts(net):
    """
    Start dhclient on all Mininet hosts with names beginnning with 'h'.
    :param net: Mininet network object.
    :return: None
    """
    print("--- Runnning dhclient ---")
    run_commands(net.hosts, ["dhclient"], lambda x: re.match(r'h\d+', x.name))


def remove_all_ARP_cache(net):
    """
    Empty the ARP cache of all Mininet hosts with names beginnning with 'h'.
    :param net: Mininet network object
    :return: None
    """
    run_commands(net.hosts, ["ip - s - s neigh flush all"], lambda x: re.match(r'h\d+', x.name))


def disable_ipv6(net):
    """
    Disable IPv6 on all network elements in Mininet network.
    :param net: Mininet network object.
    :return: None
    """
    print('--- Disabling IPv6 in network nodes ---')
    for node in (net.hosts + net.switches):
        node.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1')
        node.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1')
        node.cmd('sysctl -w net.ipv6.conf.lo.disable_ipv6=1')


def del_switch_flows(switch):
    """
    Remove all flows on a switch.
    :param switch: Mininet Switch object.
    :return: None
    """
    switch.cmd("ovs-ofctl del-flows {}".format(switch.name))


def del_all_flows(net):
    """
    Remove all flows on all switches in a Mininet network.
    :param net: Mininet network object
    :return: None
    """
    for switch in net.switches:
        del_switch_flows(switch)


def run_commands(nodes, commands, filter=lambda x: x):
    """
    Run a specified command on Mininet network nodes. Can specify a filter to exclude some of the Mininety nodes.
    :param nodes: Mininet Node objects.
    :param commands: Command, likely for bash.
    :param filter: A function for filtering. Return true on desired nodes, and false for all others.
    :return: None
    """
    for node in nodes:
        for command in commands:
            if filter(node):
                node.cmd(command)


def filter_nodes(nodes, filter=lambda x: x):
    filtered_nodes = []
    for node in nodes:
        if filter(node):
            filtered_nodes.append(node)
    return filtered_nodes
