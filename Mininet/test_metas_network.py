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

def create_network():
    net = Containernet(controller=RemoteController, link=TCLink)
    net.addController(name="c0", ip='127.0.0.1', port=6653)

    o1 = net.addHost('o1', ip="10.0.2.10/24", mac="00:00:00:00:01:01")
    r1 = net.addHost('r1', ip="10.0.1.1/24", mac="00:00:00:00:00:01")  # Router  
    s1 = net.addSwitch('s1', dpid='0000000000000001') 
    h3 = net.addDocker("h3", ip="10.0.1.3", dimage="tleemcjr/metasploitable2")
    h4 = net.addDocker("h4", ip="10.0.1.4", dimage="rightscale/openvas")

    linkparams = {'delay': '0.5ms'} 
    net.addLink(s1, r1, port1=1, **linkparams)
    net.addLink(s1, h3, port1=2, **linkparams)
    net.addLink(s1, h4, port1=3, **linkparams)
    net.addLink(r1, o1, bw=10, delay='15ms')  # Delay is doubled as it is applied on interfaces
    net.addLink(h3, o1, bw=10, delay='15ms')
    return net


def start_network(net):
    # Fetch all hosts from the network
    r1 = net.get('r1')
    o1 = net.get('o1')

    # Extra configurations to network
    net.start()
    topo_helper.disable_ipv6(net)
    topo_helper.configure_router(r1, ("10.0.1.1/24", "10.0.2.1/24")) # add two subnet interfaces to router1
    topo_helper.add_default_route(net, r1.IP())
    o1.cmd("ip route add default via 10.0.2.1")
    # o1.cmd('route add -net 10.0.1.0 netmask 255.255.255.0 gw 10.0.2.1 o1-eth0')

    h3 = net.get('h3')
    h4 = net.get('h4')
    # start Metasploitable services
    h3.cmd("/bin/services.sh")

    h4.cmd("openvas-mkcert -f \n\n\n\n\n\n\n")
    h4.cmd("openvas-mkcert-client -i -n")
    h4.cmd('openvasmd '+\
        '--modify-scanner "08b69003-5fc2-4037-a479-93b440211c73" '+\
        '--scanner-ca-pub /usr/local/var/lib/openvas/CA/cacert.pem '+\
        '--scanner-key-pub  /usr/local/var/lib/openvas/CA/clientcert.pem '+\
        '--scanner-key-priv /usr/local/var/lib/openvas/private/CA/clientkey.pem')
    h4.cmd('service redis-server restart')
    h4.cmd('/openvas/startup.sh & ')

    net.start()
    CLI(net)
    net.stop()


def main():
    net = create_network()
    start_network(net)

if __name__ == '__main__':
    main()