import ipaddress
import json
import os
from datetime import datetime, timezone

_CONN_LOG_FIELDS = frozenset({
    'ts', 'id.orig_h', 'id.resp_h', 'id.resp_p',
    'proto', 'service', 'duration', 'orig_bytes',
    'conn_state'
})

_CONN_STATE_MAP = {
    'S0': 'SYN sent, no response received',
    'S1': 'Connection established, not closed',
    'SF': 'Normal connection setup and proper closure',
    'REJ': 'Connection attempt rejected',
    'S2': 'Connection established, initiator tried to close, no responder reply',
    'S3': 'Connection established, responder tried to close, no initiator reply',
    'RSTO': 'Initiator reset (aborted) the connection',
    'RSTR': 'Responder reset the connection',
    'RSTOS0': 'Initiator sent SYN then RST, no SYN-ACK seen',
    'RSTRH': 'Responder sent SYN-ACK then RST, no SYN from initiator seen',
    'SH': 'Initiator sent SYN then FIN, connection half-open',
    'SHR': 'Responder sent SYN-ACK then FIN, no SYN from initiator',
    'OTH': 'Midstream traffic only, no SYN observed',
}


def enrich_conn_state(row):
    """Add conn_state_desc to a conn.log row in-place."""
    conn_state = row.get('conn_state')
    row['conn_state_desc'] = _CONN_STATE_MAP.get(str(conn_state).upper(), conn_state) if conn_state else None
    return row

def _cast_value(value, field_type):
    """Cast a raw TSV string value to its Zeek type."""
    if value == '-':
        return None
    if field_type in {'count', 'int'}:
        try:
            return int(value)
        except ValueError:
            return value
    if field_type in {'double', 'interval'}:
        try:
            return float(value)
        except ValueError:
            return value
    return value


def _parse_tsv_line(line, fields, types):
    """Convert a TSV data line into a dict using the header fields/types."""
    values = line.split('\t')
    if len(values) != len(fields):
        return None
    return {
        field: _cast_value(values[i], types[i] if i < len(types) else None)
        for i, field in enumerate(fields)
        if field in _CONN_LOG_FIELDS
    }


def _process_line(line, fields, types):
    """Parse a single data line; return a log entry dict/object or None."""
    try:
        if line.startswith('{'):
            return json.loads(line)
        if fields:
            return _parse_tsv_line(line, fields, types)
    except Exception:
        pass
    return None


def parse_zeek_log(log_path):
    """Parse Zeek TSV/JSON log files without external dependencies."""
    logs = []
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as handle:
            fields, types = [], []
            for line in handle:
                line = line.strip()
                if not line or line.startswith('#separator'):
                    continue
                if line.startswith('#fields'):
                    fields = line.split('\t')[1:]
                    continue
                if line.startswith('#types'):
                    types = line.split('\t')[1:]
                    continue
                if line.startswith('#'):
                    continue
                entry = _process_line(line, fields, types)
                if entry is not None:
                    logs.append(entry)
        return logs
    except Exception:
        return []

def get_internal_tcp_udp_ips_from_conn_log(log_path):
    """Return sorted unique internal IPs from conn.log, limited to TCP/UDP traffic."""
    return get_internal_tcp_udp_ip_aggregation_from_conn_log(log_path)["ips"]


_CGN = ipaddress.ip_network('100.64.0.0/10')


def _is_bogon(addr):
    """Return True if addr is a reserved/bogon address that should be excluded."""
    try:
        ip = ipaddress.ip_address(addr)
    except Exception:
        return True
    if ip.is_multicast or ip.is_loopback or ip.is_unspecified or ip.is_link_local:
        return True
    if _CGN.supernet_of(ipaddress.ip_network(f"{ip}/32")):
        return True
    return ip.is_reserved and not ip.is_private


def _collect_row_ips(row, internal_ips):
    """Add internal IPs from a single conn.log row into the set."""
    if str(row.get("local_orig") or "").upper() == "T":
        ip = row.get("id.orig_h")
        if ip:
            internal_ips.add(ip)
    if str(row.get("local_resp") or "").upper() == "T":
        ip = row.get("id.resp_h")
        if ip:
            internal_ips.add(ip)


def get_internal_tcp_udp_ip_aggregation_from_conn_log(log_path):
    """Return unique TCP/UDP internal IPs and their count from conn.log."""
    internal_ips = set()
    try:
        for row in parse_zeek_log(log_path):
            if str(row.get("proto") or "").lower() not in {"tcp", "udp"}:
                continue
            _collect_row_ips(row, internal_ips)
    except Exception:
        return {"ips": [], "count": 0}
    filtered = sorted(addr for addr in internal_ips if not _is_bogon(addr))
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


def _get_es_status(context):
    """Add Elasticsearch connectivity info to context in-place."""
    try:
        from elastic import get_es
        es = get_es()
        context["elasticsearch_connected"] = es is not None
    except Exception as exc:
        context["elasticsearch_connected"] = False
        context["elasticsearch_error"] = str(exc)


def _get_zeek_logs_stats(zeek_logs_folder):
    """Return pcap_dirs, conn_logs, and latest_mtime for a zeek_logs folder."""
    pcap_dirs = conn_logs = 0
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
    return pcap_dirs, conn_logs, latest_mtime


def get_site_status_context():
    context = {"zeek_parser_available": True}
    _get_es_status(context)
    zeek_logs_folder = os.path.join(os.path.abspath(os.path.dirname(__file__)), "zeek_logs")
    if os.path.isdir(zeek_logs_folder):
        pcap_dirs, conn_logs, latest_mtime = _get_zeek_logs_stats(zeek_logs_folder)
        context["zeek_log_pcap_count"] = pcap_dirs
        context["zeek_conn_log_count"] = conn_logs
        if latest_mtime is not None:
            context["zeek_latest_log_utc"] = datetime.fromtimestamp(
                latest_mtime, timezone.utc
            ).isoformat()
    return context