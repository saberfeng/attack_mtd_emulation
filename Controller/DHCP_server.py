"""
DHCP_server.py
A class implementation of a DHCP although this is only used for key storage and generation as this point.
"""
__author__ = "Cole Dishington"
__email__ = "cole.dishington@pg.canterbury.ac.nz"
__status__ = "Developement"

from random import SystemRandom  # cryptographically secure random number generator as implemented by OS
import Controller.controller_helper as ch


class DHCPServer(object):
    def __init__(self, subnet, netmask, static_ips={}, _range=None):
        """
        Class implementation of a DHCP server.

        Although it is not a true DHCP server for the following reasons;
        a constant lease time is taken over all hosts, and it doesn't run over the network.
        The lease time is constant over all hosts to avoid outside entities from tracking the one-by-one IP changes
        and thus never losing information after multiplexing has occured.
        This class does not run over the network and rather as a class on the controller as unlike most DHCP servers
        its only client is the controller and therefore inorder to reduce complexity and wasted bandwidth the server
        was moved onto the controller.

        :param subnet: Subnet that addresses are generated for.
        :param netmask: Netmask paired with the subnet.
        :param range: Array containing two IP addresses that specify the lower and upper of the range of IP addresses
        that will be generated
        :param lease_time: lease time allocated to addresses by default, measured in seconds.
        """
        self.allocations = static_ips.copy()

        # Generate the widest range, excluding broadcast address, if none is specified
        if _range is None:
            # Range, excluding broadcast address
            lower = ch.bitwise_ip_and(subnet, netmask)
            upper = ch.bitwise_ip_or(lower, ch.bitwise_ip_neg(ch.bitwise_ip_or(netmask, "0.0.0.1")))

            ip_range = (lower, upper)
        else:
            ip_range = _range

        # Potentially check the input values are correct
        self.subnet = subnet
        self.netmask = netmask
        self.range = ip_range
        self.static_ips = static_ips
        self.generator = SystemRandom()

    def release_all(self):
        self.allocations = self.static_ips.copy()

    def release(self, rip):
        """
        Release the virtual IP address associated with the specified real IP address
        :param rip:
        :return: True, if the specified mac address was removed from those allocated. False the specified mac had
        no address allocated.
        """
        ip = self.allocations.get(rip)
        if ip and not self.static_ips.get(rip):
            self.allocations.pop(rip)
            return True
        return False

    def request(self, rip, vip=None, is_static=False):
        """
        Requests an IP from the DNS server
        :param rip: The real IP address of the host that virtual ip will be mapped from.
        :param vip: Requested vIP address
        :param is_static: boolean to mark if the requested IP is to be static
        :return: Returns the generated IP address, this may not be the same as the passed address.
        """
        if not self.allocations.get(rip):
            if vip and vip not in self.allocations.values():
                self.allocations[rip] = vip
            else:
                start, end = self.range
                vip = ch.gen_rng_ip(self.netmask, start, end, self.generator)
                while vip in self.allocations.values():
                    vip = ch.gen_rng_ip(self.netmask, start, end, self.generator)
                self.allocations[rip] = vip

        if is_static:
            self.static_ips[rip] = self.allocations[rip]

        return self.allocations[rip]



class FRVM_DHCPServer(object):
    def __init__(self, subnet, netmask, static_ips={}, _range=None):
        """
        Class implementation of a DHCP server.

        Although it is not a true DHCP server for the following reasons;
        a constant lease time is taken over all hosts, and it doesn't run over the network.
        The lease time is constant over all hosts to avoid outside entities from tracking the one-by-one IP changes
        and thus never losing information after multiplexing has occured.
        This class does not run over the network and rather as a class on the controller as unlike most DHCP servers
        its only client is the controller and therefore inorder to reduce complexity and wasted bandwidth the server
        was moved onto the controller.

        :param subnet: Subnet that addresses are generated for.
        :param netmask: Netmask paired with the subnet.
        :param range: Array containing two IP addresses that specify the lower and upper of the range of IP addresses
        that will be generated
        :param lease_time: lease time allocated to addresses by default, measured in seconds.
        """
        self.allocations = static_ips.copy()

        # Generate the widest range, excluding broadcast address, if none is specified
        if _range is None:
            # Range, excluding broadcast address
            # subnet:10.0.1.0  mask:255.255.255.0
            # lower :10.0.1.0  higher: 10.0.1.254
            lower = ch.bitwise_ip_and(subnet, netmask)
            upper = ch.bitwise_ip_or(lower, ch.bitwise_ip_neg(ch.bitwise_ip_or(netmask, "0.0.0.1")))
            ip_range = (lower, upper)
        else:
            ip_range = _range

        # Potentially check the input values are correct
        self.subnet = subnet
        self.netmask = netmask
        self.range = ip_range
        self.static_ips = static_ips
        self.generator = SystemRandom()

    def release_all(self):
        self.allocations = self.static_ips.copy()

    def release(self, rip, port):
        """
        Release the virtual IP address associated with the specified real IP address
        :param rip:
        :param port
        :return: True, if the specified mac address was removed from those allocated. False the specified mac had
        no address allocated.
        """
        key = (rip, port)
        ip = self.allocations.get(key)
        if ip and not self.static_ips.get(key):
            self.allocations.pop(key)
            return True
        return False

    def request(self, rip, port, vip=None, is_static=False):
        """
        Requests an IP from the DNS server
        :param rip: The real IP address of the host that virtual ip will be mapped from.
        :param vip: Requested vIP address
        :param is_static: boolean to mark if the requested IP is to be static
        :return: Returns the generated IP address, this may not be the same as the passed address.
        """
        # self.allocations -> 
        # {
        #   (rip, port) : (vip, port)
        # }
        key = (rip, port)
        if not self.allocations.get(key):

            if vip and not ch.find(self.allocations.values(), vip, lambda x: x[0]):
                # if provided vip and vip is not in current allocations, just use it
                self.allocations[(rip, port)] = (vip, port)
            else:
                start, end = self.range
                vip = ch.gen_rng_ip(self.netmask, start, end, self.generator)
                # if we get a vip twice, keep generate until we have a new unique vip
                while ch.find(self.allocations.values(), vip, lambda x: x[0]):
                    vip = ch.gen_rng_ip(self.netmask, start, end, self.generator)
                self.allocations[key] = (vip, port)

        if is_static:
            self.static_ips[key] = self.allocations[key]

        return self.allocations[key]
