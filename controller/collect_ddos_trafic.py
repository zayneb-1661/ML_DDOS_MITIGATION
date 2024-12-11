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

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(10)

    def request_stats(self, datapath):
        self.logger.debug('Send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()
        body = ev.msg.body

        with open("FlowStatsfile.csv", "a+") as file0:
            for stat in sorted(
                [flow for flow in body if flow.priority == 1],
                key=lambda flow: (
                    flow.match.get('eth_type', 0),
                    flow.match.get('ipv4_src', '0.0.0.0'),
                    flow.match.get('ipv4_dst', '0.0.0.0'),
                    flow.match.get('ip_proto', 0)
                )
            ):
                ip_src = stat.match.get('ipv4_src', '0.0.0.0')
                ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
                ip_proto = stat.match.get('ip_proto', 0)

                icmp_code = stat.match.get('icmpv4_code', -1)
                icmp_type = stat.match.get('icmpv4_type', -1)
                tp_src = stat.match.get('tcp_src', 0) or stat.match.get('udp_src', 0)
                tp_dst = stat.match.get('tcp_dst', 0) or stat.match.get('udp_dst', 0)

                flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"

                try:
                    packet_count_per_second = stat.packet_count / stat.duration_sec
                except ZeroDivisionError:
                    packet_count_per_second = 0

                try:
                    byte_count_per_second = stat.byte_count / stat.duration_sec
                except ZeroDivisionError:
                    byte_count_per_second = 0

                file0.write(
                    f"{timestamp},{ev.msg.datapath.id},{flow_id},{ip_src},{tp_src},"
                    f"{ip_dst},{tp_dst},{ip_proto},{icmp_code},{icmp_type},"
                    f"{stat.duration_sec},{stat.duration_nsec},"
                    f"{stat.idle_timeout},{stat.hard_timeout},{stat.flags},"
                    f"{stat.packet_count},{stat.byte_count},"
                    f"{packet_count_per_second},0,{byte_count_per_second},0,1\n"
                )
