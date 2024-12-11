from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from switch import SimpleSwitch13
from datetime import datetime
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score


class SimpleMonitor13(SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        start = datetime.now()
        self.flow_training()
        end = datetime.now()
        self.logger.info("Training time: %s", (end - start))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug("Register datapath: %016x", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug("Unregister datapath: %016x", datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug("Send stats request: %016x", datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        try:
            timestamp = datetime.now().timestamp()
            body = ev.msg.body
            data = []

            for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow:
                               (flow.match['eth_type'], flow.match.get('ipv4_src', ''),
                                flow.match.get('ipv4_dst', ''), flow.match['ip_proto'])):
                ip_src = stat.match.get('ipv4_src', '0.0.0.0')
                ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
                ip_proto = stat.match['ip_proto']

                tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
                tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))
                icmp_code = stat.match.get('icmpv4_code', -1)
                icmp_type = stat.match.get('icmpv4_type', -1)

                flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"
                packet_count_per_second = stat.packet_count / stat.duration_sec if stat.duration_sec > 0 else 0
                byte_count_per_second = stat.byte_count / stat.duration_sec if stat.duration_sec > 0 else 0

                data.append([
                    timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst, ip_proto,
                    icmp_code, icmp_type, stat.duration_sec, stat.duration_nsec, stat.idle_timeout,
                    stat.hard_timeout, stat.flags, stat.packet_count, stat.byte_count,
                    packet_count_per_second, 0, byte_count_per_second, 0
                ])

            if not data:
                self.logger.warning("No flow data collected.")
                return

            flow_df = pd.DataFrame(data, columns=[
                'timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst', 'tp_dst',
                'ip_proto', 'icmp_code', 'icmp_type', 'flow_duration_sec', 'flow_duration_nsec',
                'idle_timeout', 'hard_timeout', 'flags', 'packet_count', 'byte_count',
                'packet_count_per_second', 'packet_count_per_nsecond', 'byte_count_per_second',
                'byte_count_per_nsecond'
            ])

            flow_df['ip_src'] = flow_df['ip_src'].str.replace('.', '', regex=False)
            flow_df['ip_dst'] = flow_df['ip_dst'].str.replace('.', '', regex=False)
            flow_df['flow_id'] = flow_df['flow_id'].str.replace('.', '', regex=False)
            

            X_predict_flow = flow_df.iloc[:, :].values.astype('float64')  # Use all but the last 2 columns
            if X_predict_flow.size == 0:
                self.logger.warning("Prediction input array is empty.")
                return

            y_flow_pred = self.flow_model.predict(X_predict_flow)
            legitimate_traffic = sum(1 for pred in y_flow_pred if pred == 0)
            ddos_traffic = len(y_flow_pred) - legitimate_traffic
            self.logger.info('prediction is ',y_flow_pred)
            self.logger.info("Traffic Stats - Legitimate: %s%%, DDoS: %s%%",
                             (legitimate_traffic / len(y_flow_pred)) * 100,
                             (ddos_traffic / len(y_flow_pred)) * 100)

        except Exception as e:
            self.logger.error("Error in _flow_stats_reply_handler: %s", str(e))

    def flow_training(self):
        try:
            self.logger.info("Flow Training ...")

            flow_dataset = pd.read_csv('FlowStatsfile.csv')
            flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '', regex=False)
            flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '', regex=False)
            flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '', regex=False)

            X_flow = flow_dataset.iloc[:, :-1].values.astype('float64')  # All but the label column
            y_flow = flow_dataset.iloc[:, -1].values  # Label column

            X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(
                X_flow, y_flow, test_size=0.25, random_state=0)

            classifier = RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=0)
            self.flow_model = classifier.fit(X_flow_train, y_flow_train)

            y_flow_pred = self.flow_model.predict(X_flow_test)

            self.logger.info("Confusion Matrix:\n%s", confusion_matrix(y_flow_test, y_flow_pred))
            acc = accuracy_score(y_flow_test, y_flow_pred)
            self.logger.info("Accuracy = %.2f%%", acc * 100)
            self.logger.info("Fail Rate = %.2f%%", (1 - acc) * 100)
        except Exception as e:
            self.logger.error("Error during flow training: %s", str(e))
