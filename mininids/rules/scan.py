from ..bounded import scope
from ..protocols import RST
from .common import Items, table


class ScanRule:
    def __init__(self, config, emit):
        self.config, self.emit = config, emit
        self.probes = table(config)
        self.tables = [self.probes]
        self.item_evictions = 0

    def window(self, key, now, create=False):
        window = self.probes.get(key, now)
        if window is None and create:
            window = self.probes.put(
                key, Items(self.config.max_window_items, self.config.window_seconds), now
            )
        if window:
            window.prune(now)
        return window

    def report(self, packet, key, window, now):
        if not window or len(window.items) < self.config.scan_ports:
            return
        src, dst, proto = key[-3:]
        statuses = [value[1][1] for value in window.items.values()]
        methods = {
            "SCAN-1": statuses.count("syn_scan"),
            "SCAN-2": statuses.count("connect"),
            "SCAN-3": statuses.count("icmp_unreachable"),
        }
        rule = "SCAN-UDP" if proto == "UDP" else "SCAN-TCP"
        threshold = self.config.scan_ports
        for candidate, count in methods.items():
            if count >= threshold:
                rule = candidate
        self.emit(
            packet,
            rule,
            "Port Scan",
            src,
            dst,
            {
                "protocol": proto,
                "distinct_ports": len(window.items),
                "ports_sample": sorted(window.items)[:32],
                "classifications": dict(
                    (status, statuses.count(status)) for status in sorted(set(statuses))
                ),
                "threshold": threshold,
                "window_seconds": self.config.window_seconds,
                "classification": {
                    "SCAN-1": "SYN",
                    "SCAN-2": "Connect",
                    "SCAN-3": "UDP with ICMP",
                    "SCAN-UDP": "UDP probes",
                    "SCAN-TCP": "indeterminate TCP probes",
                }[rule],
            },
            key,
        )

    def process(self, packet, now, event):
        ip, tcp, udp, icmp = packet.ip, packet.tcp, packet.udp, packet.icmp
        prefix = scope(packet)
        if tcp and event and event.flow.initiator is not None:
            flow = event.flow
            if flow.initiator == 0:
                src, sport, dst, dport = flow.src, flow.src_port, flow.dst, flow.dst_port
            else:
                src, sport, dst, dport = flow.dst, flow.dst_port, flow.src, flow.src_port
            key = (prefix, src, dst, "TCP")
            window = self.window(key, now, event.syn_new)
            if window is None:
                return
            if event.syn_new:
                old_evictions = window.evictions
                window.put(dport, (sport, "probe"), now)
                self.item_evictions += window.evictions - old_evictions
            item = window.items.get(dport)
            if item and item[1][0] == sport:
                status = item[1][1]
                if event.synack_new:
                    status = "syn_ack"
                if event.established_new:
                    status = "connect"
                if tcp.flags & RST and status == "syn_ack" and event.direction == flow.initiator:
                    status = "syn_scan"
                if tcp.flags & RST and status == "probe" and event.direction != flow.initiator:
                    status = "closed"
                # Replies do not extend probe observation time.
                window.items[dport] = (item[0], (sport, status))
            self.report(packet, key, window, now)
        elif udp:
            key = (prefix, ip.src, ip.dst, "UDP")
            window = self.window(key, now, True)
            old_evictions = window.evictions
            window.put(udp.dst_port, (udp.src_port, "probe"), now)
            self.item_evictions += window.evictions - old_evictions
            self.report(packet, key, window, now)
        elif icmp and icmp.type == 3 and icmp.code == 3 and icmp.embedded_ip:
            inner = icmp.embedded_ip
            if inner.protocol != 17:
                return
            key = (prefix, inner.src, inner.dst, "UDP")
            window = self.window(key, now)
            item = window.items.get(icmp.embedded_dst_port) if window else None
            if item and item[1][0] == icmp.embedded_src_port:
                window.items[icmp.embedded_dst_port] = (item[0], (item[1][0], "icmp_unreachable"))
                self.report(packet, key, window, now)
