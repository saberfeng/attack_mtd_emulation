"""
tSDN_controller.py
A Ryu application to perform Ethernet-level routing. This is used as a comparision to the FRVM controller application.
"""
__author__ = "Cole Dishington"
__email__ = "cole.dishington@pg.canterbury.ac.nz"
__status__ = "Development"

# Ryu app and OpenFlow libraries
from ryu.base import app_manager  # Helps with ryu app development such as registering
from ryu.controller import ofp_event  # Import some triggerable
from ryu.ofproto import ofproto_v1_2  # import the versions app is compatible with
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls  # After negotiating

# Ryu packages to process packets
from ryu.lib.packet import packet, ethernet, ether_types

ETH_BROADCAST = "ff:ff:ff:ff:ff:ff"
IDLE_TIMEOUT = 60
HARD_TIMEOUT = 0


class L2Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @staticmethod
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

    @staticmethod
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
        if not in_port:
            in_port = msg.match['in_port']

        # buffer_id of 0xffffffff denotes the payload having a raw packet

        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=0xffffffff, in_port=in_port,
            actions=actions, data=msg.data)
        dp.send_msg(out)

    def handle_eth_pkt(self, dp, msg, eth_pkt):
        """
        Processes the Ethernet packet contained in the packet-in packet to achieve Ethernet-level routing in the network
        using the flow-mod and packet-out OpenFlow mechanisms.
        :param dp: Datapath of switch that sent packet-in.
        :param msg: Packet-in, sent by the switch identified by dp.
        :param eth_pkt: Ethernet packet taken from msg.
        :return: None
        """
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.mac_to_port.setdefault(dp.id, {})
        in_port = msg.match['in_port']
        self.mac_to_port[dp.id][eth_pkt.src] = in_port # 检查这里的eth_pkt.src到底是什么，检查性能

        # Checking if both directions of the route are known.
        if eth_pkt.dst in self.mac_to_port[dp.id].keys():
            out_port = self.mac_to_port.get(dp.id).get(eth_pkt.dst)
        else:
            out_port = dp.ofproto.OFPP_FLOOD

        # Add flow if both inward and outward ports of switch are known
        actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
        if out_port != dp.ofproto.OFPP_FLOOD:
            match = dp.ofproto_parser.OFPMatch(
                in_port=in_port,
                eth_dst=eth_pkt.dst, eth_src=eth_pkt.src)
            self.add_flow(dp, match, actions)

        self.pkt_out(dp, msg, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Decorator calls this function on a packet_in msg is recieved, although only after
        negotiation wih the switch is finished (MAIN_DISPATCHER).
        :param ev: EventOFPPacketIn object
        :return: None
        """
        msg = ev.msg  # OpenFlow msg received
        dp = msg.datapath  # Sending switch

        pkt = packet.Packet(msg.data)  # Payload of the msg
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt:
            # Only need ethernet layer routing on inner switches
            self.handle_eth_pkt(dp, msg, eth_pkt)
