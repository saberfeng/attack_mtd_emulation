#!/usr/bin/python2.7
"""
networks.py
Creates virtual networks with the use of Mininet's Python API. All networks configured are split into multiple
subnetworks, a SDN-based network and outside users. This simulates users connecting to the protected network via the
Internet. Input is generated by generate_config.py, such as number of hosts, scan types, controller type, ...
"""

import topo_helper
from itertools import cycle
from collections import OrderedDict
import sys
import os.path
import json
import time
import re

# Mininet imports
from mininet.net import Containernet
from mininet.node import RemoteController, Controller
from mininet.cli import CLI
from mininet.clean import Cleanup
from mininet.log import setLogLevel
from mininet.topo import Topo  # Parent to topology class
from mininet.link import TCLink

Topos = {}

TCP_SCANS = ("sS", "sT", "sN", "sF", "sX")
UDP_SCANS = ("sU")

def read_config():
    """
    Read in JSON config file.
    :return: Dictionary containing the content in the config file.
    """
    f = open("./Ryu/hosts_ports.json")
    content = json.loads(f.read())
    f.close()
    return content

# class NmapNetwork(Topo):
#     """
#     Configures a network containing
#     """
#     def __init__(self):
#         Topo.__init__(self)

#         self.config = read_config()
#         self.num_hosts = int(self.config.get("num_hosts"))
#         self.controller_type = self.config.get("controller_type")

#         r1 = self.addHost('r1', ip="10.0.1.1/24", mac="00:00:00:00:00:01")  # Router
#         a2 = self.addHost('a2', ip="10.0.1.2/24", mac="00:00:00:00:00:02")  # Attacker
#         o1 = self.addHost('o1', ip="10.0.2.10/24", mac="00:00:00:00:01:01")  # Outsider

#         # Static number of switches
#         linkparams = {'delay': '0.5ms'}  # Default link params
#         s1 = self.addSwitch('s1', dpid='0000000000000001')
#         s2 = self.addSwitch('s2', dpid='0000000000000002')
#         s3 = self.addSwitch('s3', dpid='0000000000000003')
#         self.addLink(s1, r1, port1=1, **linkparams)
#         self.addLink(s1, a2, port1=4, **linkparams) # debug
#         self.addLink(s2, s1, port1=1, port2=2, **linkparams)
#         self.addLink(s3, s1, port1=1, port2=3, **linkparams)
#         # self.addLink(s4, s1, port1=1, port2=4, **linkparams)
#         # self.addLink(s5, s1, port1=1, port2=5, **linkparams)
#         self.addLink(r1, o1, bw=10, delay='15ms')  # Delay is doubled as it is applied on interfaces
#         c = cycle([s1, s2, s3])

#         # rIPs of hosts begin from 2
#         for i in range(3, 3 + int(self.num_hosts)):
#             if i == 3:
#                 # h3 : openvas
#                 host = self.addHost("h{}".format(i), ip="10.0.1.{}/24".format(i), dimage="rightscale/openvas")
#             elif i == 6:
#                 # h6 : metasploitable
#                 host = self.addHost("h{}".format(i), ip="10.0.1.{}/24".format(i), dimage="tleemcjr/metasploitable2")
#             else:
#                 host = self.addHost("h{}".format(i), ip="10.0.1.{}/24".format(i))
#             self.addLink(next(c), host, **linkparams)

#     # def port_per_host(self):
#     #     """
#     #     Find the minimum size of a set of ports inwhich there is a single port per host
#     #     :return:
#     #     """
#     #     port_set = set()
#     #     for i in range(self.num_hosts):
#     #         port_set.add(self.config.get(str(i))[0])
#     #     return port_set

#     def run(self):
#         controller = RemoteController('c0', '127.0.0.1', 6653)

#         net = Containernet(topo=self, controller=controller, link=TCLink)
#         # Fetch all hosts from the network
#         r1 = net.get('r1')
#         o1 = net.get('o1')

#         # Extra configurations to network
#         net.start()
#         topo_helper.disable_ipv6(net)
#         topo_helper.configure_router(r1, ("10.0.1.1/24", "10.0.2.1/24")) # add two subnet interfaces to router1
#         topo_helper.add_default_route(net, r1.IP())
#         o1.cmd("ip route add default via 10.0.2.1")

#         # Opening correct ports
#         topo_helper.open_host_ports(net, self.config, "udp")
#         # scan_type = self.config.get("scan_type")
#         # if scan_type in TCP_SCANS:
#         #     topo_helper.open_host_ports(net, self.config, "tcp") # open http servers on given ports
#         # elif scan_type in UDP_SCANS:
#         #     topo_helper.open_host_ports(net, self.config, "udp")
#         self.generate_switch_connections_file(net)
#         net.start()
#         CLI(net)
#         net.stop()
    
#     def generate_switch_connections_file(self, net):
#         result = {}
#         for switch in net.switches:
#             result[switch.dpid] = {}
#             for port in switch.intfs:
#                 if port == 0: # port0 is loopback
#                     continue
#                 interface = switch.intfs[port]
#                 connected_interface = self.get_connected_interface(interface)
#                 connected_node = connected_interface.node
#                 if re.match(r'^h\d+$|^r\d+$', connected_node.name):
#                     result[switch.dpid][port] = (connected_node.name, connected_interface.ip)
#                 elif re.match(r'^s\d+$', connected_node.name):
#                     result[switch.dpid][port] = (connected_node.name, connected_node.dpid)
#         print(result)
#         with open("switch_connections.json", "w") as f:
#             json.dump(result, f, indent=4, sort_keys=True)
    
#     def get_connected_interface(self, interface):
#         if interface.link: # interface itself is in a link
#             link_intfs = [ interface.link.intf1, interface.link.intf2 ]
#             link_intfs.remove(interface) # remove itself, the left is the other interface
#             return link_intfs[0]


# Topos["NmapNetwork"] = NmapNetwork



#------------------Containernet---------------------------------------------------------------------------------------

def create_network(config, is_containernet):
    net = Containernet(controller=RemoteController, link=TCLink)
    net.addController(name="c0", ip='127.0.0.1', port=6653)
    
    num_hosts = int(config.get("num_hosts"))
    controller_type = config.get("controller_type")

    o1 = net.addHost('o1', ip="10.0.4.10/22", mac="00:00:00:00:01:01")  # Outsider
    if is_containernet:
        r1 = net.addDocker('r1', ip="10.0.0.1/22", mac="00:00:00:00:00:01", dimage="rightscale/openvas")  # Router
        a2 = net.addDocker('a2', ip="10.0.0.2/22", mac="00:00:00:00:00:02", dimage="hal3002/metasploit")
    else:    
        r1 = net.addHost('r1', ip="10.0.0.1/22", mac="00:00:00:00:00:01")
        a2 = net.addHost('a2', ip="10.0.0.2/22", mac="00:00:00:00:00:02")

    # Static number of switches
    linkparams = {'delay': '0.5ms'}  # Default link params
    s1 = net.addSwitch('s1', dpid='0000000000000001')
    s2 = net.addSwitch('s2', dpid='0000000000000002')
    s3 = net.addSwitch('s3', dpid='0000000000000003')
    net.addLink(s1, r1, port1=1, **linkparams)
    net.addLink(s1, a2, port1=4, **linkparams)
    net.addLink(s2, s1, port1=1, port2=2, **linkparams)
    net.addLink(s3, s1, port1=1, port2=3, **linkparams)
    net.addLink(r1, o1, bw=10, delay='15ms')  # Delay is doubled as it is applied on interfaces
    c = cycle([s1, s2, s3])

    # rIPs of hosts begin from 2
    for i in range(3, 3 + int(num_hosts)):
        if i == 6 and is_containernet:
            # h6 : metasploitable
            host = net.addDocker("h{}".format(i), ip="10.0.0.{}/22".format(i), dimage="tleemcjr/metasploitable2")
        else:
            host = net.addHost("h{}".format(i), ip="10.0.0.{}/22".format(i))
        net.addLink(next(c), host, **linkparams)
    return net

def start_network(net, config, is_containernet):
    # Fetch all hosts from the network
    r1 = net.get('r1')
    o1 = net.get('o1')

    # Extra configurations to network
    net.start()
    topo_helper.disable_ipv6(net)
    topo_helper.configure_router(r1, ("10.0.0.1/22", "10.0.4.1/22")) # add two subnet interfaces to router1
    topo_helper.add_default_route(net, r1.IP())
    o1.cmd("ip route add default via 10.0.4.1")

    if is_containernet:
        h6 = net.get('h6')
        # start Metasploitable services
        h6.cmd("/bin/services.sh")
        # start openvas services
        r1.cmd("openvas-mkcert -f \n\n\n\n\n\n\n")
        r1.cmd("openvas-mkcert-client -i -n")
        r1.cmd('openvasmd '+\
            '--modify-scanner "08b69003-5fc2-4037-a479-93b440211c73" '+\
            '--scanner-ca-pub /usr/local/var/lib/openvas/CA/cacert.pem '+\
            '--scanner-key-pub  /usr/local/var/lib/openvas/CA/clientcert.pem '+\
            '--scanner-key-priv /usr/local/var/lib/openvas/private/CA/clientkey.pem')
        r1.cmd('service redis-server restart')
        r1.cmd('/openvas/startup.sh & ')
        # r1.cmd('route add -net 10.0.1.0 netmask 255.255.255.0 gw 10.0.2.1 o1-eth0')
    else:
        # Opening udp ports
        topo_helper.open_host_ports(net, config, "udp")
    generate_switch_connections_file(net)
    net.start()
    CLI(net)
    net.stop()

def generate_switch_connections_file(net):
    result = {}
    for switch in net.switches:
        result[switch.dpid] = {}
        for port in switch.intfs:
            if port == 0: # port0 is loopback
                continue
            interface = switch.intfs[port]
            connected_interface = get_connected_interface(interface)
            connected_node = connected_interface.node
            if re.match(r'^h\d+$|^r\d+$|^a\d+$', connected_node.name):
                result[switch.dpid][port] = (connected_node.name, connected_interface.ip)
            elif re.match(r'^s\d+$', connected_node.name):
                result[switch.dpid][port] = (connected_node.name, connected_node.dpid)
    print(result)
    with open("switch_connections.json", "w") as f:
        json.dump(result, f, indent=4, sort_keys=True)

def get_connected_interface(interface):
    if interface.link: # interface itself is in a link
        link_intfs = [ interface.link.intf1, interface.link.intf2 ]
        link_intfs.remove(interface) # remove itself, the left is the other interface
        return link_intfs[0]

def main():
    # if len(sys.argv) < 2:
    #     print("*** Error: Missing parameters ***")
    # else:
    #     topo = sys.argv[1]
    #     top = Topos.get(topo, lambda x: x)()
    #     top.run()
    config = read_config()
    is_containernet = False
    net = create_network(config, is_containernet)
    start_network(net, config, is_containernet)


if __name__ == '__main__':
    setLogLevel('info')
    main()