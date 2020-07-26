import json
import time
from collections import namedtuple
from threading import Timer
import re

# Ryu app and OpenFlow libraries
from ryu.base import app_manager  # Helps with ryu app developement such as registering
from ryu.controller import ofp_event  # Import some triggerable
from ryu.ofproto import ofproto_v1_3  # import the versions app is compatible with
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls  # After negotiating
# Ryu packages to process packets
from ryu.lib.packet import packet, ipv4, arp, icmp, tcp, udp, ethernet, ether_types

from Controller.DHCP_server import FRVM_DHCPServer
import Controller.controller_helper as helper

# IP class
IP = namedtuple('IP', ['address', 'netmask', 'subnet'])
ADDRESS = IP("10.0.1.0", "255.255.255.0", "10.0.1.0/24")
STATIC_IPS = {("10.0.1.1", True): ("10.0.1.1", True)}
IP_BROADCAST = "255.255.255.255"
ETH_BROADCAST = "ff:ff:ff:ff:ff:ff"

Proto_IPv4 = "IPv4"
Proto_ARP = "ARP"

class FRVM(app_manager.RyuApp):
    """
    Implementation of FRVM with multiple vIP per host in terms of ports (and an additional vIP for portless protocols
    like icmp).
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FRVM, self).__init__(*args, **kwargs)
        self.mac_to_switch_port = {}
        self.switch_connections = load_json_file("switch_connections.json")
        self.config = load_json_file("./Ryu/hosts_ports.json")
        self.num_hosts = int(self.config.get("num_hosts"))
        self.lease_period = int(self.config.get("mtd_time"))

        self.dhcp_server = FRVM_DHCPServer(ADDRESS.address, ADDRESS.netmask, STATIC_IPS,
                                      ('10.0.1.{}'.format(self.num_hosts + 4), '10.0.1.254'))
        # item -> ((rip, port), (vip, port))
        self.rip_to_vip = {}  # (rip, port) => (vip, port)
        self.allocate_vip(self.rip_to_vip)

        self.new_rip_to_vip = {} # next round
        self.allocate_vip(self.new_rip_to_vip)

        self.timer = Timer(self.lease_period, self.create_timer)
        self.started = time.time()
        self.timer.start()
    
    def remaining_time(self):
        return self.lease_period - int(time.time() - self.started)
    
    def create_timer(self):
        print("*** Generating next round vips ***")
        self.rip_to_vip = self.new_rip_to_vip
        self.new_rip_to_vip = {}

        self.allocate_vip(self.new_rip_to_vip)
        self.dhcp_server.release_all()
        print("current:", self.rip_to_vip)
        print("next round:", self.new_rip_to_vip)

        self.timer = Timer(self.lease_period, self.create_timer)
        self.started = time.time()
        self.timer.start()

    def allocate_vip(self, rip_to_vip):
        for i in range(self.num_hosts):
            ports = self.config.get(str(i))
            rip = "10.0.1.{}".format(3+i)
            print("host {} opening ports {}".format(rip, " ".join(map(str, ports))))
            for port in ports + [Proto_ARP, "ICMP"]: # extra for portless protocols ARP, ICMP
                rip_to_vip[(rip, port)] = self.dhcp_server.request("10.0.1.{}".format(i), port)
        self.dhcp_server.release_all()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions, hard_timeout=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, hard_timeout=hard_timeout)
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg

        pkt = packet.Packet(msg.data)  # Payload of the msg
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP: # ignore lldp packet
            return
        
        if arp_pkt:
            self.arp_route(msg) # change parameters
        elif ip_pkt:
            self.ip_route(msg)
    
    def learn_mac_address(self, msg):
        in_port = msg.match['in_port']
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        self.mac_to_switch_port.setdefault(datapath.id, {})
        self.mac_to_switch_port[datapath.id][eth.src] = in_port
        self.logger.info("packet in dpid={} src={} dst={} in_port={}".format(datapath.id, eth.src, eth.dst, in_port))
        return in_port, datapath, pkt, eth.src, eth.dst
    
    def get_src_dst_port(self, pkt):
        # Portless protocols
        arp_pkt = pkt.get_protocol(arp.arp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        # Transport layet protocols
        udp_pkt = pkt.get_protocol(udp.udp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if arp_pkt:
            return Proto_ARP, Proto_ARP
        elif icmp_pkt:
            return "ICMP", "ICMP"
        elif udp_pkt:
            return udp_pkt.src_port, udp_pkt.dst_port
        elif tcp_pkt:
            return tcp_pkt.src_port, tcp_pkt.dst_port
    
    
    def ip_route(self, msg):
        in_port, datapath, pkt, eth_src, eth_dst = self.learn_mac_address(msg)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if eth_dst in self.mac_to_switch_port[datapath.id][eth_src]: # if the dst mac is learned
            out_port = self.mac_to_switch_port[datapath.id][eth_dst]
            match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
            src_port, dst_port = self.get_src_dst_port(pkt)
            actions = self.get_actions(datapath, in_port, out_port, ip_pkt.src, ip_pkt.dst, src_port, dst_port, Proto_IPv4)

            if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
                self.add_flow(
                    datapath=datapath, 
                    priority=1, 
                    match=match,
                    actions=actions,
                    hard_timeout=self.remaining_time())
                self.packet_out(msg, actions, in_port)
            else:
                self.add_flow(
                    datapath=datapath, 
                    priority=1, 
                    match=match,
                    actions=actions,
                    hard_timeout=self.remaining_time(),
                    buffer_id=msg.buffer_id)
                return
        else: # we flood this packet
            self.flood_packet(msg, in_port, ip_pkt.src, ip_pkt.dst, src_port, dst_port, Proto_IPv4) # modify

    def arp_route(self, msg):
        in_port, datapath, pkt, eth_src, eth_dst = self.learn_mac_address(msg)
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth_dst in self.mac_to_switch_port[datapath.id][eth_src]: # if the dst mac is learned
            out_port = self.mac_to_switch_port[datapath.id][eth_dst]
            match = datapath.ofproto_parser.OFPMatch(eth_type=0x0806, arp_spa=arp_pkt.src_ip, arp_tpa=arp_pkt.dst_ip)
            actions = self.get_actions(
                datapath, 
                in_port, out_port, 
                arp_pkt.src_ip, arp_pkt.dst_ip, 
                src_port=Proto_ARP, dst_port=Proto_ARP,
                protocol=Proto_ARP)

            if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
                self.add_flow(
                    datapath=datapath, 
                    priority=1, 
                    match=match,
                    actions=actions,
                    hard_timeout=self.remaining_time())
                self.packet_out(msg, actions, in_port)
            else:
                self.add_flow(
                    datapath=datapath, 
                    priority=1, 
                    match=match,
                    actions=actions,
                    hard_timeout=self.remaining_time(),
                    buffer_id=msg.buffer_id)
                return
        else: # we flood this packet
            self.flood_packet(msg, in_port, arp_pkt.src_ip, arp_pkt.dst_ip,
                src_port=Proto_ARP, dst_port=Proto_ARP, protocol=Proto_ARP)
    
    def flood_packet(self, msg, in_port, src_ip, dst_ip, src_port, dst_port, protocol):
        for out_port in self.switch_connections.get(msg.datapath.id):
            if out_port == in_port:
                continue
            actions = self.get_actions(msg.datapath, in_port, out_port, src_ip, dst_ip, src_port, dst_port, protocol)
            self.packet_out(msg, actions, in_port)

    def packet_out(self, msg, actions, in_port):
        datapath = msg.datapath
        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def get_actions(self, datapath, in_port, out_port, src_ip, dst_ip, src_port, dst_port, protocol):
        if self.is_edge_port(datapath.id, in_port, protocol): # packet is from edge port
            if self.is_edge_port(datapath.id, out_port, protocol): # packet is going to edge port
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            else:
                new_src_ip, new_dst_ip = src_ip, dst_ip
                # if source ip is host rip:
                if find_in_dict(self.rip_to_vip, (src_ip, src_port), lambda item: item[0]): # item->((rip, port), (vip, port))
                    new_src_ip = self.rip_to_vip[(src_ip, src_port)][0] # change source rip to vip
                # if dst ip is host rip:
                if find_in_dict(self.rip_to_vip, (dst_ip, dst_port), lambda item: item[0]): # item->((rip, port), (vip, port))
                    new_dst_ip = self.rip_to_vip[(dst_ip, dst_port)][0] # change source rip to vip
                
                if protocol == Proto_IPv4:
                    actions = [datapath.ofproto_parser.OFPActionSetField(ipv4_src=new_src_ip, ipv4_dst=new_dst_ip),
                               datapath.ofproto_parser.OFPActionOutput(out_port)]
                elif protocol == Proto_ARP:
                    actions = [datapath.ofproto_parser.OFPActionSetField(arp_spa=new_src_ip, arp_tpa=new_dst_ip),
                               datapath.ofproto_parser.OFPActionOutput(out_port)]
        else: # packet is from non-edge port
            if self.is_edge_port(datapath.id, out_port, protocol): # packet is going to edge port
                new_src_ip, new_dst_ip = src_ip, dst_ip
                # if source ip is host vip:
                found_item = find_in_dict(self.rip_to_vip, (src_ip, src_port), lambda item: item[1])
                if found_item:
                    new_src_ip = found_item[0][0] # change source vip to rip
                # if dst ip is host vip:
                found_item = find_in_dict(self.rip_to_vip, (dst_ip, dst_port), lambda item: item[1])
                if found_item:
                    new_dst_ip = found_item[0][0] # change source vip to rip

                if protocol == Proto_IPv4:
                    actions = [datapath.ofproto_parser.OFPActionSetField(ipv4_src=new_src_ip, ipv4_dst=new_dst_ip),
                            datapath.ofproto_parser.OFPActionOutput(out_port)]
                elif protocol == Proto_ARP:
                    actions = [datapath.ofproto_parser.OFPActionSetField(arp_spa=new_src_ip, arp_tpa=new_dst_ip),
                           datapath.ofproto_parser.OFPActionOutput(out_port)]
            else:
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            return actions

    def is_edge_port(self, datapath_id, port, protocol) -> bool:
        connected_node_name, _ = self.switch_connections.get(datapath_id).get(port)
        if re.match(r'^s\d+$', connected_node_name): # this port is connected to a switch -> non-edge port
            return False
        elif re.match(r'^h\d+$', connected_node_name): # this port is connected to a host -> edge port
            return True
        elif re.match(r'^r\d+$', connected_node_name):
            if protocol == Proto_ARP: # for ARP, the port connecting router is edge port
                return True
            elif protocol == Proto_IPv4: # for IP, the port connecting router is non-edge port
                return False
            else:
                raise Exception("do not support other protocol")
        else:
            raise Exception("can't accept the node name:{}".format(connected_node_name))

    # def get_actions_ARP(self, datapath, in_port, out_port, source_ip, target_ip):
    #     if self.is_edge_port(datapath.id, in_port, Proto_ARP): # packet is from edge port
    #         if self.is_edge_port(datapath.id, out_port, Proto_ARP): # packet is going to edge port
    #             actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
    #         else: # packet is going to non-edge port
    #             new_source_ip, new_target_ip = source_ip, target_ip
    #             # if source ip is host rip:
    #             if find_in_dict(self.rip_to_vip, source_ip, lambda item: item[0][0]): # item->((rip, port), (vip, port))
    #                 new_source_ip = self.rip_to_vip[(source_ip, Proto_ARP)][0] # change source rip to vip
    #             # if target ip is host rip:
    #             if find_in_dict(self.rip_to_vip, target_ip, lambda item: item[0][0]): # item->((rip, port), (vip, port))
    #                 new_target_ip = self.rip_to_vip[(target_ip, Proto_ARP)][0] # change source rip to vip
    #             actions = [datapath.ofproto_parser.OFPActionSetField(arp_spa=new_source_ip, arp_tpa=new_target_ip),
    #                        datapath.ofproto_parser.OFPActionOutput(out_port)]
        
    #     else: # packet is from non-edge port
    #         if self.is_edge_port(datapath.id, out_port, Proto_ARP): # packet is going to edge port
    #             new_source_ip, new_target_ip = source_ip, target_ip
    #             # if source ip is host vip:
    #             found_item = find_in_dict(self.rip_to_vip, source_ip, lambda item: item[1][0])
    #             if found_item:
    #                 new_source_ip = found_item[0][0] # change source vip to rip
    #             # if target ip is host vip:
    #             found_item = find_in_dict(self.rip_to_vip, target_ip, lambda item: item[1][0])
    #             if found_item:
    #                 new_target_ip = found_item[0][0] # change source vip to rip
    #             actions = [datapath.ofproto_parser.OFPActionSetField(arp_spa=new_source_ip, arp_tpa=new_target_ip),
    #                        datapath.ofproto_parser.OFPActionOutput(out_port)]
    #         else: # packet is going to non-edge port
    #             actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
    #     return actions

def load_json_file(file_path) -> dict:
    with open(file_path, "r") as f:
        return json.load(f)

def find_in_dict(dictionary:dict, match, method=lambda x: x):
    for item in dictionary.items():
        if method(item) == match:
            return item
    return False


