from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from switch import SimpleSwitch13
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score

class SimpleMonitor13(SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.flow_model = None  # Initialize flow_model to avoid attribute error

        start = datetime.now()
        try:
            self.flow_training()
        except Exception as e:
            self.logger.error("Error during flow training: %s", str(e))
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
            if self.flow_model is None:
                self.logger.warning("Flow model is not initialized. Skipping flow prediction.")
                return

            body = ev.msg.body
            data = []

            for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow:
                               (flow.match['eth_type'], flow.match.get('ipv4_src', ''),
                                flow.match.get('ipv4_dst', ''), flow.match['ip_proto'])):
                ip_src = stat.match.get('ipv4_src', '0.0.0.0')
                ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
                ip_proto = stat.match['ip_proto']

                if not self._is_valid_ipv4(ip_src) or not self._is_valid_ipv4(ip_dst):
                    self.logger.error("Invalid IPv4 address: %s or %s", ip_src, ip_dst)
                    continue

                tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
                tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))
                icmp_code = stat.match.get('icmpv4_code', -1)
                icmp_type = stat.match.get('icmpv4_type', -1)

                packet_count_per_second = stat.packet_count / stat.duration_sec if stat.duration_sec > 0 else 0
                byte_count_per_second = stat.byte_count / stat.duration_sec if stat.duration_sec > 0 else 0

                data.append([
                    stat.duration_sec, stat.duration_nsec, stat.idle_timeout, stat.hard_timeout,
                    stat.flags, stat.packet_count, stat.byte_count,
                    packet_count_per_second, byte_count_per_second
                ])

            if not data:
                self.logger.warning("No valid flow data collected.")
                return

            flow_df = pd.DataFrame(data, columns=[
                'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout', 'hard_timeout',
                'flags', 'packet_count', 'byte_count',
                'packet_count_per_second', 'byte_count_per_second'
            ])

            X_predict_flow = flow_df.values.astype('float64')

            if X_predict_flow.shape[1] != self.flow_model.n_features_in_:
                self.logger.error("Mismatch in feature count: Expected %d, got %d", 
                                  self.flow_model.n_features_in_, X_predict_flow.shape[1])
                return

            y_flow_pred = self.flow_model.predict(X_predict_flow)

            for i, pred in enumerate(y_flow_pred):
                if pred == 1:  # DDoS detected
                    self._block_traffic(ev.msg.datapath, ip_src, ip_dst)
                    self.logger.info("Blocked traffic from %s to %s as DDoS attack detected.", ip_src, ip_dst)
                else:  # Legitimate traffic
                    self.logger.info("Forwarding legitimate traffic from %s to %s.", ip_src, ip_dst)

        except Exception as e:
            self.logger.error("Error in _flow_stats_reply_handler: %s", str(e))

    def _is_valid_ipv4(self, address):
        parts = address.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        return True

    def _block_traffic(self, datapath, ip_src, ip_dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(ipv4_src=ip_src, ipv4_dst=ip_dst, eth_type=0x0800)
        actions = []

        self.logger.info("Installing flow to block traffic from %s to %s.", ip_src, ip_dst)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=100, match=match,
            instructions=inst, hard_timeout=60, idle_timeout=30
        )
        datapath.send_msg(mod)

    def flow_training(self):
        try:
            self.logger.info("Flow Training ...")

            # Load the dataset
            flow_dataset = pd.read_csv('FlowStatsfile.csv')
            self.logger.info("Dataset loaded successfully with %d rows.", len(flow_dataset))

            # Validate dataset and clean invalid data
            flow_dataset = flow_dataset.dropna()

            feature_columns = [
                'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout', 'hard_timeout',
                'flags', 'packet_count', 'byte_count',
                'packet_count_per_second', 'byte_count_per_second'
            ]

            missing_cols = [col for col in feature_columns if col not in flow_dataset.columns]
            if missing_cols:
                self.logger.error("Missing columns in dataset: %s", missing_cols)
                return

            X_flow = flow_dataset[feature_columns].values.astype('float64')
            y_flow = flow_dataset['label'].values

            # Split dataset into training and test sets
            X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(
                X_flow, y_flow, test_size=0.25, random_state=0
            )

            # Train the RandomForest model
            classifier = RandomForestClassifier(n_estimators=10, criterion="entropy", random_state=0)
            self.flow_model = classifier.fit(X_flow_train, y_flow_train)

            # Evaluate the model
            y_flow_pred = self.flow_model.predict(X_flow_test)
            self.logger.info("Confusion Matrix:\n%s", confusion_matrix(y_flow_test, y_flow_pred))
            acc = accuracy_score(y_flow_test, y_flow_pred)
            self.logger.info("Accuracy = %.2f%%", acc * 100)
            self.logger.info("Fail Rate = %.2f%%", (1 - acc) * 100)
        except Exception as e:
            self.logger.error("Error during flow training: %s", str(e))
