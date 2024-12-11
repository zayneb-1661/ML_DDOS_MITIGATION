import switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from datetime import datetime

class CollectTrainingStatsApp(switch.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(CollectTrainingStatsApp, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self.monitor)

        # Open file for writing the flow stats headers
        with open("FlowStatsfile.csv", "w") as file0:
            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond,label\n')

    # Asynchronous message handler for state changes
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    # Monitor thread to periodically request stats from switches
    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(10)

    # Request flow stats from the datapath
    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # Handler for flow stats reply event
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        # Open file for appending flow stats
        with open("FlowStatsfile.csv", "a+") as file0:
            body = ev.msg.body
            for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow: (
                flow.match.get('eth_type', None),
                flow.match.get('ipv4_src', None),
                flow.match.get('ipv4_dst', None),
                flow.match.get('ip_proto', None)
            )):

                # Safely access flow match fields
                ip_src = stat.match.get('ipv4_src', None)
                ip_dst = stat.match.get('ipv4_dst', None)
                ip_proto = stat.match.get('ip_proto', None)

                if ip_proto == 1:  # ICMP
                    icmp_code = stat.match.get('icmpv4_code', -1)
                    icmp_type = stat.match.get('icmpv4_type', -1)
                elif ip_proto == 6:  # TCP
                    tp_src = stat.match.get('tcp_src', 0)
                    tp_dst = stat.match.get('tcp_dst', 0)
                elif ip_proto == 17:  # UDP
                    tp_src = stat.match.get('udp_src', 0)
                    tp_dst = stat.match.get('udp_dst', 0)

                flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"

                # Calculate packet and byte count per second
                try:
                    packet_count_per_second = stat.packet_count / stat.duration_sec
                    packet_count_per_nsecond = stat.packet_count / stat.duration_nsec
                except ZeroDivisionError:
                    packet_count_per_second = 0
                    packet_count_per_nsecond = 0

                try:
                    byte_count_per_second = stat.byte_count / stat.duration_sec
                    byte_count_per_nsecond = stat.byte_count / stat.duration_nsec
                except ZeroDivisionError:
                    byte_count_per_second = 0
                    byte_count_per_nsecond = 0

                # Write stats to file
                file0.write(f"{timestamp},{ev.msg.datapath.id},{flow_id},{ip_src},{tp_src},{ip_dst},{tp_dst},"
                            f"{ip_proto},{icmp_code},{icmp_type},{stat.duration_sec},{stat.duration_nsec},"
                            f"{stat.idle_timeout},{stat.hard_timeout},{stat.flags},{stat.packet_count},{stat.byte_count},"
                            f"{packet_count_per_second},{packet_count_per_nsecond},{byte_count_per_second},{byte_count_per_nsecond},0\n")
            file0.close()