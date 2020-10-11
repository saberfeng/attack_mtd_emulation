import json
import time
from collections import namedtuple
from threading import Timer
from datetime import datetime
import re

# Ryu app and OpenFlow libraries
from ryu.base import app_manager  # Helps with ryu app developement such as registering
from ryu.controller import ofp_event  # Import some triggerable
from ryu.ofproto import ofproto_v1_3  # import the versions app is compatible with
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls  # After negotiating
# Ryu packages to process packets
from ryu.lib.packet import packet, ipv4, arp, icmp, tcp, udp, ethernet, ether_types

from DHCP_server import FRVM_DHCPServer
import controller_helper as helper

# IP class
IP = namedtuple('IP', ['address', 'netmask', 'subnet'])
ADDRESS = IP("10.0.1.0", "255.255.255.0", "10.0.1.0/24")
STATIC_IPS = {("10.0.1.1", True): ("10.0.1.1", True)}
IP_BROADCAST = "255.255.255.255"
ETH_BROADCAST = "ff:ff:ff:ff:ff:ff"

Proto_IPv4 = "IPv4"
Proto_ARP = "ARP"
Proto_TCP = "TCP"
Proto_UDP = "UDP"
Proto_ICMP = "ICMP"

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
        self.switch_port_to_gateway = {}
        self.get_switch_port_to_gateway()
        self.config = load_json_file("./Ryu/hosts_ports.json")
        self.num_hosts = int(self.config.get("num_hosts"))
        self.lease_period = int(self.config.get("mtd_time"))

        self.switch_flood_group_ids = {}
        self.flood_group_id = 1
        self.init_flood_group_ids()

        self.dhcp_server = FRVM_DHCPServer(ADDRESS.address, ADDRESS.netmask, STATIC_IPS,
                                      ('10.0.0.{}'.format(self.num_hosts + 4), '10.0.3.254'))
        # item -> ((rip, port), (vip, port))
        self.rip_to_vip = {}  # (rip, port) => (vip, port)
        self.allocate_vip(self.rip_to_vip)
        self.print_rip_to_vip()

        self.new_rip_to_vip = {} # next round
        self.allocate_vip(self.new_rip_to_vip)

        self.timer = Timer(self.lease_period, self.create_timer)
        self.started = time.time()
        self.timer.start()
        self.arp_buffer = {}

    def print_rip_to_vip(self):
        metasploitable_vips = ""
        with open("rip_vip", "a+") as f:
            f.write("\ntime: " + str(datetime.now()) + "\n")
            for item in self.rip_to_vip.items():
                # print vips
                print(item)
                # write to file
                f.write(str(item) + "\n")
                # # list all vips of 10.0.0.6
                # if item[0][0] == "10.0.0.6":
                #     metasploitable_vips += "," + item[1][0]
            f.write(metasploitable_vips)
        
    # self.switch_port_to_gateway
    # records those switch ports connecting between outside and FRVM network
    # the "outside" can be in the same subnet
    # structure: 
    # {
    #   datapath_id_1:[switch_port_1, switch_port_2],
    #   datapath_id_2:[switch_port_1],
    # }
    def get_switch_port_to_gateway(self):
        for datapath_id in self.switch_connections:
            for port in self.switch_connections[datapath_id]:
                node_name, _ = self.switch_connections[datapath_id][port]
                # if the node connected to this port is "r1" or "a2", save this datapath and port
                if re.match(r'^r\d+$|^a\d+$', node_name): 
                    create_key_in_dict(self.switch_port_to_gateway, datapath_id, [])
                    self.switch_port_to_gateway[datapath_id].append(int(port))

    def get_new_group_id(self):
        group_id = self.flood_group_id
        self.flood_group_id += 1
        return group_id
    
    def init_flood_group_ids(self):
        """
        self.switch_flood_group_ids ->
        {
            "0000000000000001":{
                1:1,
                2:2,
                3:3,
                4,4,
                5,5
            },
            "0000000000000002":{
                1:6,
                2:7,
                3:8
            },
            "0000000000000003": {
                1: 9,
                2: 10
            }
        }
        """
        for datapath_id in self.switch_connections:
            self.switch_flood_group_ids[datapath_id] = {}
    
    def remaining_time(self):
        return self.lease_period - int(time.time() - self.started)
    
    def create_timer(self):
        print("*** Generating next round vips ***")
        self.rip_to_vip = self.new_rip_to_vip
        self.new_rip_to_vip = {}
        self.print_rip_to_vip()

        self.allocate_vip(self.new_rip_to_vip)
        self.dhcp_server.release_all()
        # print("next round:", self.new_rip_to_vip)

        self.timer = Timer(self.lease_period, self.create_timer)
        self.started = time.time()
        self.timer.start()

    def allocate_vip(self, rip_to_vip):
        for i in range(self.num_hosts):
            ports = self.config.get(str(i))
            rip = "10.0.0.{}".format(3+i)
            # print("host {} opening ports {}".format(rip, " ".join(map(str, ports))))
            for port in ports + [Proto_ARP, "ICMP"]: # extra for portless protocols ARP, ICMP
                rip_to_vip[(rip, port)] = self.dhcp_server.request("10.0.0.{}".format(i), port)
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
        print()
    
    def learn_mac_address(self, msg):
        in_port = msg.match['in_port']
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        datapath_id = str(datapath.id).zfill(16)
        self.mac_to_switch_port.setdefault(datapath_id, {})
        self.mac_to_switch_port[datapath_id][eth.src] = in_port
        self.logger.info("packet in dpid={} src={} dst={} in_port={}".format(datapath_id, eth.src, eth.dst, in_port))
        return in_port, datapath, datapath_id, pkt, eth.src, eth.dst
    
    def get_src_dst_port(self, pkt):
        # Portless protocols
        arp_pkt = pkt.get_protocol(arp.arp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        # Transport layet protocols
        udp_pkt = pkt.get_protocol(udp.udp)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if arp_pkt:
            return Proto_ARP, Proto_ARP, Proto_ARP
        elif icmp_pkt:
            return Proto_ICMP, Proto_ICMP, Proto_ICMP
        elif udp_pkt:
            return udp_pkt.src_port, udp_pkt.dst_port, Proto_UDP
        elif tcp_pkt:
            return tcp_pkt.src_port, tcp_pkt.dst_port, Proto_TCP
    
    def get_ip_match_by_proto(self, datapath, eth_type, ipv4_src, ipv4_dst, src_port, dst_port, proto):
        if proto == Proto_TCP:
            return datapath.ofproto_parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=6,
                ipv4_src=ipv4_src, 
                ipv4_dst=ipv4_dst,
                tcp_src=src_port,
                tcp_dst=dst_port)
        elif proto == Proto_UDP:
            print("*"*20)
            print(ipv4_src, ipv4_dst, src_port, dst_port)
            return datapath.ofproto_parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=17,
                ipv4_src=ipv4_src, 
                ipv4_dst=ipv4_dst,
                udp_src=src_port,
                udp_dst=dst_port)
        elif proto == Proto_ICMP:
            return datapath.ofproto_parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=1,
                ipv4_src=ipv4_src, 
                ipv4_dst=ipv4_dst
            )
    
    def ip_route(self, msg):
        in_port, datapath, datapath_id, pkt, eth_src, eth_dst = self.learn_mac_address(msg)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        src_port, dst_port, proto = self.get_src_dst_port(pkt)
        if eth_dst in self.mac_to_switch_port[datapath_id]: # if the dst mac is learned
            out_port = self.mac_to_switch_port[datapath_id][eth_dst]

            # src_port, dst_port, tcp_or_udp = self.get_src_dst_port(pkt)
            match = self.get_ip_match_by_proto(
                datapath, eth_type=0x0800, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst, src_port=src_port, dst_port=dst_port, proto=proto)
            # match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
            
            actions = self.get_actions(datapath, in_port, out_port, ip_pkt.src, ip_pkt.dst, src_port, dst_port, Proto_IPv4)

            if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
                self.add_flow(
                    datapath=datapath, 
                    priority=2, 
                    match=match,
                    actions=actions,
                    hard_timeout=self.remaining_time())
                self.packet_out(msg, actions, in_port)
            else:
                self.add_flow(
                    datapath=datapath, 
                    priority=2, 
                    match=match,
                    actions=actions,
                    hard_timeout=self.remaining_time(),
                    buffer_id=msg.buffer_id)
                return
        else: # we flood this packet
            # self.add_flood_group(msg, in_port, ip_pkt.src, ip_pkt.dst, src_port, dst_port, Proto_IPv4)
            # actions = [datapath.ofproto_parser.OFPActionGroup(FLOOD_GROUP_ID)] # use the flood group 
            # self.packet_out(msg, actions, in_port)
            self.flood_packet(msg, in_port, ip_pkt.src, ip_pkt.dst, src_port, dst_port, Proto_IPv4)
    
    def find_arp_vip(self, vip):
        # input vip: the vip of a host, may not be the correct vip for arp
        found_item = find_in_dict(self.rip_to_vip, vip, lambda item: item[1][0])
        if found_item:
            rip, _ = found_item[0]
            arp_vip, _ = self.rip_to_vip.get((rip, Proto_ARP))
            return arp_vip

    def save_to_arp_buffer(self, arp_vip, datapath_id, switch_port, outsider_address, original_arp_dst):
        create_key_in_dict(self.arp_buffer, arp_vip, {})
        create_key_in_dict(self.arp_buffer[arp_vip], datapath_id, {})
        create_key_in_dict(self.arp_buffer[arp_vip][datapath_id], switch_port, {})
        create_key_in_dict(self.arp_buffer[arp_vip][datapath_id][switch_port], outsider_address, [])
        self.arp_buffer[arp_vip][datapath_id][switch_port][outsider_address].append(original_arp_dst)
        
    def modify_packets_from_gateway(self, datapath, datapath_id, in_port, arp_pkt):
        if datapath_id in self.switch_port_to_gateway and \
           in_port in self.switch_port_to_gateway[datapath_id]:
            arp_vip = self.find_arp_vip(arp_pkt.dst_ip)
            self.save_to_arp_buffer(arp_vip, datapath_id, in_port, arp_pkt.src_ip, arp_pkt.dst_ip)
            arp_pkt.dst_ip = arp_vip 
            return [datapath.ofproto_parser.OFPActionSetField(arp_tpa=arp_vip)]
        return []

    def arp_route(self, msg):
        in_port, datapath, datapath_id, pkt, eth_src, eth_dst = self.learn_mac_address(msg)
        arp_pkt = pkt.get_protocol(arp.arp)
        actions = self.modify_packets_from_gateway(datapath, datapath_id, in_port, arp_pkt)

        if eth_dst in self.mac_to_switch_port[datapath_id]: # if the dst mac is learned
            out_port = self.mac_to_switch_port[datapath_id][eth_dst]
            match = datapath.ofproto_parser.OFPMatch(eth_type=0x0806, arp_spa=arp_pkt.src_ip, arp_tpa=arp_pkt.dst_ip)
            actions += self.get_actions(
                datapath, 
                in_port, out_port, 
                arp_pkt.src_ip, arp_pkt.dst_ip, 
                src_port=Proto_ARP, dst_port=Proto_ARP,
                protocol=Proto_ARP)
            # we don't install flows for arp responses
            # because when there are multiple arp requests for different vips of the same host from the gateway router,
            # we can't decide which of these vips should we set as the arp_spa in the flow actions.
            # we have to let this controller set arp_spa dynamically
            self.packet_out(msg, actions, in_port)

        else: 
            # we flood this packet
            # all arp request will be flooded, since we can't learn the MAC address: 00:00:00:00.....
            self.flood_packet(msg, in_port, arp_pkt.src_ip, arp_pkt.dst_ip, 
                src_port=Proto_ARP, dst_port=Proto_ARP, protocol=Proto_ARP, actions=actions)
    
    def flood_packet(self, msg, in_port, src_ip, dst_ip, src_port, dst_port, protocol, actions=[]):
        group_id = self.switch_flood_group_ids.get(str(msg.datapath.id).zfill(16)).get(in_port)
        # if we already have installed a flood group for this port
        # use this group to process this packet
        if not group_id: 
            # add flood group
            group_id = self.add_or_mod_flood_group(msg, in_port, src_ip, dst_ip, src_port, dst_port, protocol, actions=actions)
            # print("*"*20 + "\ngroup_id:{} datapath_id:{} src_ip:{} dst_ip:{}\n".format(group_id, msg.datapath.id, src_ip, dst_ip) + "*"*20)
            self.switch_flood_group_ids[str(msg.datapath.id).zfill(16)][in_port] = group_id # update mapping
            # self.debug_print_group_ids()
        else:
            # update flood group to use latest vips
            self.add_or_mod_flood_group(msg, in_port, src_ip, dst_ip, src_port, dst_port, protocol, group_id, actions=actions)
        group_action = [msg.datapath.ofproto_parser.OFPActionGroup(group_id)] 
        self.packet_out(msg, group_action, in_port)

    def add_or_mod_flood_group(self, msg, in_port, src_ip, dst_ip, src_port, dst_port, protocol, group_id=None, actions=[]):
        buckets = []
        datapath_id = str(msg.datapath.id).zfill(16)
        for out_port in self.switch_connections.get(datapath_id):
            out_port = int(out_port)
            if out_port == in_port:
                continue
            more_actions = self.get_actions(msg.datapath, in_port, out_port, src_ip, dst_ip, src_port, dst_port, protocol)
            buckets.append(msg.datapath.ofproto_parser.OFPBucket(weight=0, actions=actions+more_actions))
        if group_id is None:
            group_id = self.get_new_group_id()
            req = msg.datapath.ofproto_parser.OFPGroupMod(
                msg.datapath, 
                msg.datapath.ofproto.OFPGC_ADD, 
                msg.datapath.ofproto.OFPGT_ALL,
                group_id,
                buckets)
            msg.datapath.send_msg(req)
        else:
            req = msg.datapath.ofproto_parser.OFPGroupMod(
                msg.datapath, 
                msg.datapath.ofproto.OFPGC_MODIFY, 
                msg.datapath.ofproto.OFPGT_ALL,
                group_id,
                buckets)
            msg.datapath.send_msg(req)
        return group_id

    def packet_out(self, msg, actions, in_port):
        datapath = msg.datapath
        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=int(in_port), actions=actions, data=data)
        datapath.send_msg(out)
    
    def query_and_pop_arp(self, arp_vip, datapath_id, switch_port, outsider_address):
        if arp_vip not in self.arp_buffer or\
            datapath_id not in self.arp_buffer[arp_vip] or\
            switch_port not in self.arp_buffer[arp_vip][datapath_id] or\
            outsider_address not in self.arp_buffer[arp_vip][datapath_id][switch_port] or\
            len(self.arp_buffer[arp_vip][datapath_id][switch_port][outsider_address]) == 0:
            return None
        else:
            return self.arp_buffer[arp_vip][datapath_id][switch_port][outsider_address].pop(0)
    
    def get_arp_translating_action(self, 
            protocol, datapath, out_port, arp_vip, datapath_id, switch_port, outsider_address):
        # arp response to gateway
        if protocol == Proto_ARP and\
           datapath_id in self.switch_port_to_gateway and\
           out_port in self.switch_port_to_gateway[datapath_id]:
            arp_dst_before_modify = self.query_and_pop_arp(arp_vip, datapath_id, switch_port, outsider_address)
            if arp_dst_before_modify:
                return [datapath.ofproto_parser.OFPActionSetField(arp_spa=arp_dst_before_modify)]
        return []

    def get_arp_translating_action_old(self, datapath, arp_vip, datapath_id, switch_port, outsider_address):
        arp_dst_before_modify = self.query_and_pop_arp(arp_vip, datapath_id, switch_port, outsider_address)
        if arp_dst_before_modify:
            return [datapath.ofproto_parser.OFPActionSetField(arp_spa=arp_dst_before_modify)]
        else:
            return []

    def get_actions(self, datapath, in_port, out_port, src_ip, dst_ip, src_port, dst_port, protocol):
        datapath_id = str(datapath.id).zfill(16)
        from_edge_port = self.is_edge_port(datapath_id, in_port, protocol)
        to_edge_port = self.is_edge_port(datapath_id, out_port, protocol)
        
        if from_edge_port and to_edge_port:
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            
        elif not from_edge_port and not to_edge_port:
            actions = []
            actions += self.get_arp_translating_action(protocol, datapath, out_port, src_ip, datapath_id, out_port, dst_ip)
            actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
        elif from_edge_port and not to_edge_port:
            actions = []
            # if source ip is host rip:
            if find_in_dict(self.rip_to_vip, (src_ip, src_port), lambda item: item[0]): # item->((rip, port), (vip, port))
                new_src_ip = self.rip_to_vip[(src_ip, src_port)][0] # change source rip to vip
                proto_to_param_arg = { Proto_IPv4:{"ipv4_src":new_src_ip}, Proto_ARP:{"arp_spa":new_src_ip} }
                actions.append(datapath.ofproto_parser.OFPActionSetField(**proto_to_param_arg[protocol]))
            # if dst ip is host rip:
            if find_in_dict(self.rip_to_vip, (dst_ip, dst_port), lambda item: item[0]): # item->((rip, port), (vip, port))
                new_dst_ip = self.rip_to_vip[(dst_ip, dst_port)][0] # change source rip to vip
                proto_to_param_arg = { Proto_IPv4:{"ipv4_dst":new_dst_ip}, Proto_ARP:{"arp_tpa":new_dst_ip} }
                actions.append(datapath.ofproto_parser.OFPActionSetField(**proto_to_param_arg[protocol]))
            
            arp_vip, _ = self.rip_to_vip.get((src_ip, Proto_ARP))
            actions += self.get_arp_translating_action(protocol, datapath, out_port, arp_vip, datapath_id, out_port, dst_ip)
            actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))
        elif not from_edge_port and to_edge_port:
            actions = []
            # if source ip is host vip:
            found_item = find_in_dict(self.rip_to_vip, (src_ip, src_port), lambda item: item[1])
            if found_item:
                new_src_ip = found_item[0][0] # change source vip to rip
                proto_to_param_arg = { Proto_IPv4:{"ipv4_src":new_src_ip}, Proto_ARP:{"arp_spa":new_src_ip} }
                actions.append(datapath.ofproto_parser.OFPActionSetField(**proto_to_param_arg[protocol]))
            # if dst ip is host vip:
            found_item = find_in_dict(self.rip_to_vip, (dst_ip, dst_port), lambda item: item[1])

            if found_item:
                new_dst_ip = found_item[0][0] # change source vip to rip
                proto_to_param_arg = { Proto_IPv4:{"ipv4_dst":new_dst_ip}, Proto_ARP:{"arp_tpa":new_dst_ip} }
                actions.append(datapath.ofproto_parser.OFPActionSetField(**proto_to_param_arg[protocol]))
            actions.append(datapath.ofproto_parser.OFPActionOutput(out_port))

        return actions

    def is_edge_port(self, datapath_id, port, protocol) -> bool:
        connected_node_name, _ = self.switch_connections.get(datapath_id).get(str(port))
        if re.match(r'^s\d+$|^r\d+$|^a\d+$', connected_node_name): # this port is connected to a switch -> non-edge port
            return False
        elif re.match(r'^h\d+$', connected_node_name): # this port is connected to a host -> edge port
            return True
        else:
            raise Exception("can't accept the node name:{}".format(connected_node_name))
    
    def debug_print_group_ids(self):
        print("*********************")
        print("latest group id:", self.flood_group_id)
        print("group ids:")
        print(json.dumps(self.switch_flood_group_ids))
        print("*********************")


def load_json_file(file_path) -> dict:
    with open(file_path, "r") as f:
        return json.load(f)

def find_in_dict(dictionary:dict, match, method=lambda x: x):
    for item in dictionary.items():
        if method(item) == match:
            return item
    return False

# create key if it doesn't exists in the dictionary
def create_key_in_dict(dictionary, key, default_value):
    if key not in dictionary:
        dictionary[key] = default_value
