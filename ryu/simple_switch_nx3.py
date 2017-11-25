# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.ofproto import ether
from ryu.ofproto import inet
import networkx as nx
import ipaddress
import json
from time import sleep

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.mac_to_port = {}
        self.switches = {}
        self.switches_net = {}
        self.switches_flows = {}
        self.switches_edges_offline = []
        self.load_network_info('topology.json')
        self.print_info_enable = True

    def print_info(self, msg, *args, **kwargs):
        if self.print_info_enable:
            self.logger.info(msg, *args, **kwargs)

    def load_network_info(self, jsonFileName):
        self.logger.info("Loading topology information from json file")
        try:
            with open(jsonFileName, 'r') as f:
                data = json.load(f)
                # load everything to dictionary
                for bridge in data['bridges']:
                    self.switches_net.setdefault(bridge['datapath_id'], [])
                    for network in bridge['networks']:
                        networkInfo = (network['mac_address'], network['ip_address'], network['ip_network'], network['port'])
                        self.switches_net[bridge['datapath_id']].append(networkInfo)
        except IOError:
            self.logger.info("topology.json file not found")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # set booleans to false
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.logger.info("New switch " + str(datapath.id))
        self.switches[datapath.id] = datapath

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def reset_flow(self):
        self.print_info("Function to reset switches")
        self.switches_flows.clear()
        # reset flows on switches
        for datapath in self.switches.values():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            empty_match = parser.OFPMatch()
            flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
                                                          out_group=ofproto.OFPG_ANY, priority=1, match=empty_match)
            datapath.send_msg(flow_mod)
            # send the table-miss flow entry
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 0, empty_match, actions)

    def receive_arp(self, datapath, packet, etherFrame, inPort):
        arpPacket = packet.get_protocol(arp.arp)

        if arpPacket.opcode == 1:
            # save ip address to graph and mac address to dictionary
            arp_srcIp = arpPacket.src_ip
            arp_srcMac = etherFrame.src
            # todo check with json topology
            if arp_srcIp not in self.net:
                self.print_info(arp_srcIp + " added to graph")
                self.net.add_node(arp_srcIp)
                self.net.add_edge(datapath.id, arp_srcIp, port=inPort)
                self.net.add_edge(arp_srcIp, datapath.id)
                self.print_info(self.net.edges(data=True))
            self.mac_to_port.setdefault(datapath.id, {})
            self.mac_to_port[datapath.id][arp_srcIp] = arp_srcMac

            arp_dstIp = arpPacket.dst_ip
            self.print_info("receive ARP request from %s => %s (port%d) for IP address: %s"
                             % (etherFrame.src, etherFrame.dst, inPort, arp_dstIp))
            self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, inPort)
        elif arpPacket.opcode == 2:
            arp_srcIp = arpPacket.src_ip
            arp_srcMac = etherFrame.src
            if arp_srcIp not in self.net:
                self.print_info(arp_srcIp + " added to graph")
                self.net.add_node(arp_srcIp)
                self.net.add_edge(datapath.id, arp_srcIp, port=inPort)
                self.net.add_edge(arp_srcIp, datapath.id)
                self.print_info(self.net.edges(data=True))
            self.mac_to_port.setdefault(datapath.id, {})
            self.mac_to_port[datapath.id][arp_srcIp] = arp_srcMac
            self.print_info("receive ARP reply from %s => %s (port%d) for IP address: %s"
                             % (etherFrame.src, etherFrame.dst, inPort, arp_srcIp))


    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort):
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src
        for network in self.switches_net[datapath.id]:
            if arp_dstIp == network[1]:
                srcMac = network[0]
                self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, inPort)
                self.print_info("send ARP reply %s => %s (port%d)" % (srcMac, dstMac, inPort))
                return
        self.print_info("unknown arp request received !")

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        # request
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        # reply
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet.ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.receive_arp(datapath, pkt, eth,in_port)
            self.print_info("")
            return
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            # ignore non ip packets
            return
        ip_header = pkt.get_protocols(ipv4.ipv4)[0]
        src = ip_header.src
        src_mac = eth.src
        dst = ip_header.dst

        dpid = datapath.id

        # ignore this message with this ip address, add flow message was sended
        self.switches_flows.setdefault(datapath.id, [])
        temp_test = str(in_port) + src + dst
        if temp_test in self.switches_flows[dpid]:
            return

        self.print_info("packet in switch %s %s %s from port %s", dpid, src, dst, in_port)

        # learn a ip address/MAC address to avoid asking next time.
        if src not in self.net:
            self.print_info(src + " added to graph")
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port)
            self.net.add_edge(src, dpid)
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = src_mac

        if dst not in self.net:
            self.print_info("not in graph, look up")
            # check if I have needed information
            for key, network_list in self.switches_net.iteritems():
                for network_info in network_list:
                    # ignore if it is my ip address
                    if dst == network_info[1]:
                        self.print_info("ignore my ip address")
                        # add something in the future?
                        return
                    ip_network = ipaddress.ip_network(unicode(network_info[2]))
                    if ipaddress.ip_address(unicode(dst)) in ip_network:
                        # send arp request and ignore this packet
                        self.print_info("send ARP request")
                        self.print_info("")
                        self.send_arp(self.switches[key], 1, network_info[0], network_info[1], "ff:ff:ff:ff:ff:ff",
                                      dst, network_info[3])
            return
        else:
            path = nx.shortest_path(self.net, dpid, dst)
            next = path[path.index(dpid) + 1]
            out_port = self.net[dpid][next]['port']
            if out_port == in_port:
                # do not send to the same port
                return
            # check if this is the last switch and modify actions
            if next == dst:
                # find out mac address of port
                out_port_mac = None
                for network_info in self.switches_net[dpid]:
                    ip_network = ipaddress.ip_network(unicode(network_info[2]))
                    if ipaddress.ip_address(unicode(dst)) in ip_network:
                        out_port_mac = network_info[0]
                if out_port_mac is None:
                    self.print_info("Destination " + dst + " is not in json topology")
                    return
                actions = [parser.OFPActionSetField(eth_src=out_port_mac),
                           parser.OFPActionSetField(eth_dst=self.mac_to_port[dpid][dst]),
                           parser.OFPActionOutput(out_port)]
            else:
                actions = [parser.OFPActionOutput(out_port)]
            # install a flow to avoid packet_in next time
            self.print_info(src + " " + dst + " path found")
            match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

            self.switches_flows[datapath.id].append(str(in_port)+src+dst)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            self.print_info("")

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self.logger.info("Loading topology information:")
        # clearing all lists and graph
        self.switches_flows.clear()
        self.switches_edges_offline = []
        self.net.clear()
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)

        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        sleep(1)
        self.logger.info(self.net.edges(data=True))

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        ofpport = ev.msg.desc
        self.print_info("Change of port " + str(ofpport.port_no) + " on switch " + str(ev.msg.datapath.id)
                         + " to " + str(ofpport.state))
        if ofpport.state == 1:
            datapath_id = [ev.msg.datapath.id]
            list_edges = self.net.edges(nbunch=datapath_id, data=True)
            for e in list_edges:
                edge_port_no = e[2]['port']
                if e[0] == ev.msg.datapath.id and edge_port_no == ofpport.port_no:
                    if e not in self.switches_edges_offline:
                        self.switches_edges_offline.append(e)
                        self.net.remove_edge(e[0], e[1])
                        # remove second end of edge
                        list_edges2 = self.net.edges(nbunch=[e[1]], data=True)
                        for e2 in list_edges2:
                            if e2[1] == e[0]:
                                self.switches_edges_offline.append(e2)
                                self.net.remove_edge(e2[0], e2[1])
                        # reset flow on all switches
                        self.reset_flow()
                        self.print_info(self.net.edges(data=True))
        elif ofpport.state == 0:
            for e in self.switches_edges_offline:
                if e[0] == ev.msg.datapath.id and e[2]['port'] == ofpport.port_no:
                    self.net.add_edge(e[0], e[1], port=e[2]['port'])
                    self.switches_edges_offline.remove(e)
                    # reset flow on all switches
                    self.reset_flow()
                    self.print_info(self.net.edges(data=True))
