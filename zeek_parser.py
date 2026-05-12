"""Minimal Zeek log parser - no external dependencies beyond stdlib."""

import json
import os
from datetime import datetime, timezone

def parse_zeek_log(log_path):
    """Parse Zeek TSV/JSON log files without external dependencies."""
    logs = []
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as handle:
            fields = []
            types = []

            for line in handle:
                line = line.strip()
                if not line:
                    continue

                if line.startswith('#fields'):
                    fields = line.split('\t')[1:]
                    continue

                if line.startswith('#types'):
                    types = line.split('\t')[1:]
                    continue

                if line.startswith('#'):
                    continue

                try:
                    if line.startswith('{'):
                        logs.append(json.loads(line))
                        continue

                    if fields:
                        values = line.split('\t')
                        if len(values) != len(fields):
                            continue

                        entry = {}
                        for index, field in enumerate(fields):
                            value = values[index]
                            field_type = types[index] if index < len(types) else None

                            if value == '-':
                                entry[field] = None
                            elif field_type in {'count', 'int'}:
                                try:
                                    entry[field] = int(value)
                                except ValueError:
                                    entry[field] = value
                            elif field_type in {'double', 'interval'}:
                                try:
                                    entry[field] = float(value)
                                except ValueError:
                                    entry[field] = value
                            else:
                                entry[field] = value

                        logs.append(entry)
                except Exception:
                    continue

        return logs
    except Exception:
        return []


def get_internal_tcp_udp_ips_from_conn_log(log_path):
    """Return sorted unique internal IPs from conn.log, limited to TCP/UDP traffic."""
    return get_internal_tcp_udp_ip_aggregation_from_conn_log(log_path)["ips"]


def get_internal_tcp_udp_ip_aggregation_from_conn_log(log_path):
    """Return unique TCP/UDP internal IPs and their count from conn.log."""
    internal_ips = set()
    try:
        for row in parse_zeek_log(log_path):
            proto = str(row.get("proto") or "").lower()
            if proto not in {"tcp", "udp"}:
                continue

            if str(row.get("local_orig") or "").upper() == "T":
                ip = row.get("id.orig_h")
                if ip:
                    internal_ips.add(ip)

            if str(row.get("local_resp") or "").upper() == "T":
                ip = row.get("id.resp_h")
                if ip:
                    internal_ips.add(ip)
    except Exception:
        return {"ips": [], "count": 0}

    # Filter out reserved / bogon addresses (CGN, multicast, unspecified, loopback, link-local)
    import ipaddress

    def is_bogon(a):
        try:
            ip = ipaddress.ip_address(a)
        except Exception:
            return True
        # Exclude multicast, loopback, unspecified, link-local
        if ip.is_multicast or ip.is_loopback or ip.is_unspecified or ip.is_link_local:
            return True
        # Exclude Carrier-Grade NAT 100.64.0.0/10
        if ipaddress.ip_network('100.64.0.0/10').supernet_of(ipaddress.ip_network(str(ip) + '/32')):
            return True
        # Exclude administratively-scoped multicast 239.0.0.0/8 explicitly
        if ipaddress.ip_network('239.0.0.0/8').supernet_of(ipaddress.ip_network(str(ip) + '/32')):
            return True
        # ip.is_reserved is broad; allow excluding if it's reserved but keep private addresses
        if ip.is_reserved and not ip.is_private:
            return True
        return False

    filtered = sorted([x for x in internal_ips if not is_bogon(x)])
    return {"ips": filtered, "count": len(filtered)}


def get_internal_tcp_udp_ip_aggregation_from_conn_logs(zeek_logs_folder):
    """Return unique TCP/UDP internal IPs and their count across all conn.log files."""
    internal_ips = set()
    if not zeek_logs_folder or not os.path.isdir(zeek_logs_folder):
        return {"ips": [], "count": 0}

    try:
        for entry in os.scandir(zeek_logs_folder):
            if not entry.is_dir():
                continue

            log_path = os.path.join(entry.path, "conn.log")
            if not os.path.isfile(log_path):
                continue

            stats = get_internal_tcp_udp_ip_aggregation_from_conn_log(log_path)
            internal_ips.update(stats.get("ips", []))
    except Exception:
        return {"ips": [], "count": 0}

    ips = sorted(internal_ips)
    return {"ips": ips, "count": len(ips)}


def get_site_status_context(es, zeek_logs_folder=None):
    """Return lightweight site status details for the dashboard stats endpoint."""
    context = {"zeek_parser_available": True}

    if es is not None:
        try:
            context["elasticsearch_connected"] = bool(es.ping())
        except Exception as exc:
            context["elasticsearch_connected"] = False
            context["elasticsearch_error"] = str(exc)

    if zeek_logs_folder and os.path.isdir(zeek_logs_folder):
        pcap_dirs = 0
        conn_logs = 0
        latest_mtime = None

        for entry in os.scandir(zeek_logs_folder):
            if not entry.is_dir():
                continue

            pcap_dirs += 1
            conn_log_path = os.path.join(entry.path, "conn.log")
            if not os.path.isfile(conn_log_path):
                continue

            conn_logs += 1
            try:
                mtime = os.path.getmtime(conn_log_path)
                if latest_mtime is None or mtime > latest_mtime:
                    latest_mtime = mtime
            except OSError:
                continue

        context["zeek_log_pcap_count"] = pcap_dirs
        context["zeek_conn_log_count"] = conn_logs
        if latest_mtime is not None:
            context["zeek_latest_log_utc"] = datetime.fromtimestamp(
                latest_mtime, timezone.utc
            ).isoformat()

    return context
