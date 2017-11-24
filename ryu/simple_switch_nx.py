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
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import networkx as nx
from ryu.ofproto import ofproto_v1_3 as ofp


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.switches = {}
        self.switches_ports = {}
        self.switches_flows = {}
        self.switches_edges_blocked = []
        self.switches_edges_offline = []
        self.switches_ports_ready = True
        self.convergent = True

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # set booleans to false
        self.convergent = False
        self.switches_ports_ready = False
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

        self.logger.info("New switch " + str(ev.msg.datapath.id))
        self.switches[datapath.id] = datapath
        # send request to get status of all ports on switch
        request = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(request)

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
        self.logger.info("Function to reset switches")
        self.switches_flows.clear()
        # add blocked edges to graph and unblock them
        self.net.add_edges_from(self.switches_edges_blocked)
        for e in self.switches_edges_blocked:
            self.logger.info(e)
            src = e[0]
            src_port = e[2]['port']
            self.modify_port(src, src_port, True)
        self.switches_edges_blocked = []
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

    def modify_port(self, datapath_id, port_no, state):
        mask = (ofp.OFPPC_PORT_DOWN | ofp.OFPPC_NO_RECV |
                ofp.OFPPC_NO_FWD | ofp.OFPPC_NO_PACKET_IN)
        advertise = (ofp.OFPPF_10MB_HD | ofp.OFPPF_100MB_FD |
                     ofp.OFPPF_1GB_FD | ofp.OFPPF_COPPER |
                     ofp.OFPPF_AUTONEG | ofp.OFPPF_PAUSE |
                     ofp.OFPPF_PAUSE_ASYM)
        if state:
            config = 0
        else:
            config = (ofp.OFPPC_NO_RECV | ofp.OFPPC_NO_FWD)
        datapath = self.switches[datapath_id]
        parser = datapath.ofproto_parser
        port_hw_addr = self.switches_ports[datapath_id][port_no]
        port_msg = parser.OFPPortMod(datapath, port_no, port_hw_addr, config, mask, advertise)
        datapath.send_msg(port_msg)

    def block_ports(self, edge_list):
        if self.switches_ports_ready == False:
            # need information about ports
            return
        self.logger.info("Block ports on edges")
        for e in edge_list:
            self.logger.info(e)
            src = e[0]
            src_port = e[2]['port']
            self.modify_port(src, src_port, False)
        self.convergent = True


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if self.convergent == False:
            # network is not ready, ignore for now
            return
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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.logger.info("packet in switch %s %s %s from port %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        if src not in self.net:
            self.logger.info(src + " added to graph")
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port)
            self.net.add_edge(src, dpid)

        # ignore this message with asked network, add flow message was sended
        self.switches_flows.setdefault(datapath.id, {})
        temp_dict = self.switches_flows[dpid]
        if dst in temp_dict:
            return

        if dst in self.net:
            path = nx.shortest_path(self.net, src, dst)
            next = path[path.index(dpid) + 1]
            out_port = self.net[dpid][next]['port']
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.logger.info(src + " " + dst + " path found")
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        self.switches_flows[datapath.id][dst] = True
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.logger.info("")

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self.logger.info("Loading topology information:")
        # clearing all lists and graph
        self.switches_flows.clear()
        self.switches_edges_blocked = []
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
        self.recalculate_topology()

    def recalculate_topology(self):
        if self.switches_ports_ready == False:
            # need information about ports
            return
        self.logger.info("Recalculating the topology:")
        undirected_graph = self.net.to_undirected()
        # find biggest subgraph and generate minimum spanning tree on it
        mini_net = nx.minimum_spanning_tree(max(nx.connected_component_subgraphs(undirected_graph), key=len))
        mini_net = mini_net.to_directed()
        # show full topology
        self.logger.info("Full topology:")
        self.logger.info(self.net.edges(data=True))
        # show the minimum spanning tree
        self.logger.info("MST:")
        self.logger.info(mini_net.edges)

        # create temp graph with blocked edges (MST removed)
        directed_graph = self.net.copy()
        directed_graph.remove_edges_from(mini_net.edges)
        # save all edges needed to be disabled
        self.switches_edges_blocked = directed_graph.edges(data=True)
        # call function to block ports on this edges
        self.block_ports(self.switches_edges_blocked)
        # remove edges from main forwarding graph
        self.net.remove_edges_from(self.switches_edges_blocked)
        self.logger.info("Full without loops:")
        self.logger.info(self.net.edges(data=True))
        self.logger.info("")

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        ofpport = ev.msg.desc
        self.logger.info("Change of port on switch" + str(ev.msg.datapath.id))
        self.logger.info(ev.msg.desc)
        if ofpport.state == 1:
            datapath_id = [ev.msg.datapath.id]
            list_edges = self.net.edges(nbunch=datapath_id, data=True)
            for e in list_edges:
                edge_port_no = e[2]['port']
                if edge_port_no == ofpport.port_no:
                    if e not in self.switches_edges_offline:
                        self.switches_edges_offline.append(e)
                        self.net.remove_edge(e[0], e[1])
        elif ofpport.state == 0:
            for e in self.switches_edges_offline:
                if e[0] == ev.msg.datapath.id and e[2]['port'] == ofpport.port_no:
                    self.net.add_edge(e[0], e[1], port=e[2]['port'])
                    self.switches_edges_offline.remove(e)
        # reset flow on all switches
        self.reset_flow()
        # recreate the connection graph
        self.recalculate_topology()

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        self.switches_ports.setdefault(datapath.id, {})
        self.logger.info("Ports info from " + str(datapath.id))
        for p in ev.msg.body:
            self.switches_ports[datapath.id][p.port_no] = p.hw_addr
        # check if this is the last one
        if len(self.switches_ports) == len(self.switches):
            self.logger.info("I have all ports information")
            self.switches_ports_ready = True
            # reset flow on all switches
            self.reset_flow()
            self.recalculate_topology()
