"""
controller_helper.py
Contains various helpful functions used in Ryu applications in this package.
"""
__author__ = "Cole Dishington"
__email__ = "cole.dishington@pg.canterbury.ac.nz"
__status__ = "Developement"

from random import random
import json

BROADCAST = '255.255.255.255'
IDLE_TIMEOUT = 60
HARD_TIMEOUT = 90


def write_dict_to_file(filename, d, seperators=(',', ':')):
    file = open(filename, 'w')
    json_object = json.dumps(d, separators=seperators, indent=4)
    file.write(json_object)
    file.close()


def pkt_out(dp, msg, actions, buffer_id=None, in_port=None):
    """
    Performs the OpenFlow packet out protocol feature. If the msg does not contain buffer_id and in_port these
    can be set in the function call.
    :param dp: datapath of the switch to send a packet out.
    :param msg: packet that will be sent out through switch.
    :param actions: actions list to define how the switch will handle the packet.
    :param buffer_id: Optional argument to override value in msg.
    :param in_port: Optional argument to override value in msg
    :return: None
    """
    if not buffer_id:
        buffer_id = msg.buffer_id
    if not in_port:
        in_port = msg.match['in_port']

    out = dp.ofproto_parser.OFPPacketOut(
        datapath=dp, buffer_id=buffer_id, in_port=in_port,
        actions=actions, data=msg.data)
    dp.send_msg(out)


def add_flow(dp, match, actions, idle_timeout=IDLE_TIMEOUT, hard_timeout=HARD_TIMEOUT, flow_type=None):
    """
    Adds a flow to a switch. Sets timeouts to a constant although this constant can be set in the file.
    :param dp: Identifies switch to add flow to.
    :param match: An OPFMatch
    :param actions: Actions to perform, including which ports to output the msg on.
    :param idle_timeout:
    :param hard_timeout:
    :return: None
    """
    ofproto = dp.ofproto  # OpenFlow version of packet

    if flow_type is None:
        flow_type = ofproto.OFPIT_APPLY_ACTIONS

    instruct = dp.ofproto_parser.OFPInstructionActions(
        type_=flow_type,
        actions=actions
    )

    # Add flow entry with the flow rule matching above. This flow rule is set to be deleted instantly after
    # forwarding this first piece of traffic
    mod = dp.ofproto_parser.OFPFlowMod(
        datapath=dp, match=match, cookie=0,
        command=ofproto.OFPFC_ADD, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
        priority=0,
        flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=[instruct])
    dp.send_msg(mod)  # send msg to switch.


def read_config(filename="./Ryu/hosts_ports.json", object_pairs_hook=dict):
    f = open(filename)
    content = json.loads(f.read(), object_pairs_hook=object_pairs_hook)
    f.close()
    return content


def bin_to_dec(address_bin):
    return '.'.join([str(int(i,2)) for i in address_bin.split('.')])


def dec_to_bin(address):
    return '.'.join([format(int(i), '08b') for i in address.split('.')])


def is_byte_netmask(netmask):
    _bytes = netmask.split('.')
    if len(_bytes) == 4:
        return False
    for byte in _bytes:
        if not (0 < int(byte) <= 255):
            return False
    return True


def find(array, match, method=lambda x: x):
    """
    Generic function to allow searching through an iterable object.
    :param array: The array.
    :param match: The element (mutated or otherwise) to match in the array.
    :param method: An optional argument to mutate elements in the array.
    :return: The first matched element in the array, otherwise returns False.
    """
    if hasattr(array, '__iter__'):
        for ele in array:
            if method(ele) == match:
                return ele
    return False


def is_broadcast(address, netmask, ip):
    return ip == BROADCAST or (is_subnet(address, netmask, ip) and bitwise_ip_or(ip, netmask) == BROADCAST)


def is_subnet(address, netmask, ip):
    """
    Description
    :param address: Network address 
    :param netmask: Associated netmask with network address, written as w.x.y.z
    :param ip: Ip to test if it is in the subnet of the network
    :return: Boolean representing if the ip belongs to the network.
    """
    ip_net = bitwise_ip_and(ip, netmask)
    return ip_net == address


def is_subnets(address, netmask, ips):
    """
    Checks if a list of IP addresses (ips) belong to the subnet represented by address and netmask. Returns False
    if any of the IPs do not belong.
    :param address: Network address
    :param netmask: Associated netmask with network address, written as w.x.y.z
    :param ips: Iterable of IP addresses
    :return: Boolean representing if the ips belong to the network.
    """
    return all([is_subnet(address, netmask, ip) for ip in ips])


def bitwise_ip(addr1, addr2, op):
    res = []
    for byte1, byte2 in zip(addr1.split('.'), addr2.split('.')):
        res.append(str(op(int(byte1), int(byte2))))
    return '.'.join(res)


def bitwise_ip_or(addr1, addr2):
    return bitwise_ip(addr1, addr2, lambda x, y: x | y)


def bitwise_ip_and(addr1, addr2):
    return bitwise_ip(addr1, addr2, lambda x, y: x & y)


def bitwise_ip_neg(addr1):
    addr2 = '255.255.255.255'
    return bitwise_ip(addr1, addr2, lambda x, y: x ^ y)


def gen_rng_ip(netmask, start, end, generator=random):
    """
    Generate IPs in a range
    :param start:
    :param end:
    :param generator: A random number generator, by default a psudeo random number generator is used although
    a cryptographically secure generator could also be used.
    :return:
    """
    res = []
    for byte1, byte2, byte3 in zip(start.split('.'), end.split('.'), netmask.split('.')):
        if byte3 == '255':
            res.append(byte1)
        else:
            res.append(str(generator.randint(int(byte1), int(byte2))))

    return '.'.join(res)
