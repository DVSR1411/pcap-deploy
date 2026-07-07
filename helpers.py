from collections import defaultdict
from datetime import datetime, timezone

def scroll_all_external_ips(es_client, index):
    """Scroll through all docs in index and return a set of unique external IPs."""
    all_ips = set()
    resp = es_client.search(index=index, body={
        "query": {"match_all": {}},
        "_source": ["external_ips.ip"], "size": 500
    }, scroll="2m")
    sid = resp["_scroll_id"]
    while True:
        hits = resp["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            all_ips.update(
                e["ip"] for e in (h["_source"].get("external_ips") or []) if e.get("ip")
            )
        resp = es_client.scroll(scroll_id=sid, scroll="2m")
    try:
        es_client.clear_scroll(scroll_id=sid)
    except Exception:
        pass
    return all_ips


def rebin_time_series(data, target_bins):
    """Merge data points into at most target_bins buckets."""
    start_ts = datetime.fromisoformat(data[0]['label']).timestamp()
    end_ts = datetime.fromisoformat(data[-1]['label']).timestamp()
    interval_seconds = max(30, int((end_ts - start_ts) / target_bins))
    re_binned = defaultdict(int)
    for point in data:
        epoch = datetime.fromisoformat(point['label']).timestamp()
        re_binned[int(epoch - (epoch % interval_seconds))] += point['value']
    return [
        {"label": datetime.fromtimestamp(k, timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), "value": v}
        for k, v in sorted(re_binned.items())
    ]


def normalise_labels(data):
    """Convert ISO-8601 labels to '%Y-%m-%d %H:%M:%S' in-place."""
    for point in data:
        try:
            if 'T' in str(point['label']):
                point['label'] = datetime.fromisoformat(point['label']).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass


from collections import Counter

_INVALID_INFECTED = {'Unknown', 'N/A', '-', 'None', 'null'}
_INVALID_INFECTED_PREFIXES = ('231.', '224.', '239.')


def is_valid_infected_host(val):
    """Return True if val looks like a real infected host (not a placeholder/bogon)."""
    s = str(val).strip() if val is not None else ''
    return (
        bool(s) and
        s not in _INVALID_INFECTED and
        '::' not in s and
        not any(s.startswith(p) for p in _INVALID_INFECTED_PREFIXES)
    )


def get_pcap_ssl_domains(es_client, pcap_id):
    """Return top-10 SSL domains for a single PCAP."""
    try:
        res = es_client.search(index='pcap-dns', body={
            "query": {"term": {"pcap_id": pcap_id}},
            "_source": ["domains"], "size": 1
        })
        if not res["hits"]["hits"]:
            return []
        domains = res["hits"]["hits"][0]["_source"].get("domains", [])
        counter = Counter()
        for d in domains:
            if d.get("type") == "ssl":
                counter[d.get("domain")] += d.get("count", 0)
        return [{'label': k, 'value': v} for k, v in counter.most_common(10)]
    except Exception as e:
        print(f"Error fetching SSL domains for {pcap_id}: {e}")
        return []


def get_pcap_ip_counts(es_client, pcap_id):
    """Return (internal_ip_count, external_ip_count) for a single PCAP."""
    try:
        src = es_client.get(index='pcap-ips', id=pcap_id)["_source"]
        return len(src.get("internal_ips", [])), len(src.get("external_ips", []))
    except Exception:
        return 0, 0


def get_global_ftp_sessions(es_client):
    """Return count of PCAPs with ftp_session data."""
    try:
        res = es_client.count(index='pcap-metadata', body={
            "query": {"exists": {"field": "ftp_session"}}
        })
        return res.get('count', 0)
    except Exception:
        return 0


def build_pcap_overview_response(data, ssl_domains, internal_ip_count, external_ip_count):
    """Assemble the overview response dict for a single PCAP."""
    infected_count = 1 if is_valid_infected_host(data.get('infected_host')) else 0
    ftp_session = data.get('ftp_session') or None
    return {
        'capture_summary': {
            'file_name': data.get('pcap_filename') or data.get('file_name'),
            'pcap_packets': data.get('total_packets') or data.get('exact_pcap_packets'),
            'connections': data.get('total_connections'),
            'bytes': data.get('total_bytes'),
            'duration_seconds': data.get('duration_seconds'),
            'start_time_utc': data.get('start_time_utc'),
            'end_time_utc': data.get('end_time_utc'),
            'infected_hosts_count': infected_count,
            'internal_ip_count': internal_ip_count,
            'external_ip_count': external_ip_count,
            'ftp_sessions_count': 1 if (ftp_session and isinstance(ftp_session, dict) and any(ftp_session.values())) else 0,
        },
        'traffic_distribution': {
            'transport': data.get('transport_breakdown', []),
            'application': data.get('application_breakdown', []),
            'direction': data.get('direction_breakdown', []),
            'dns_domains': [{'domain': d.get('label'), 'count': d.get('value', 0)} for d in (data.get('top_dns_domains') or [])[:10]],
            'url_domains': [{'domain': d.get('label'), 'count': d.get('value', 0)} for d in (data.get('top_url_domains') or [])[:10]],
            'top_ssl_domains': ssl_domains,
        },
    }


def _scroll_docs(es_client, index, source_fields, size=10000):
    """Generic scroll helper; returns list of raw hit dicts."""
    docs = []
    res = es_client.search(index=index, body={
        "query": {"match_all": {}}, "_source": source_fields, "size": size
    }, scroll="2m")
    sid = res["_scroll_id"]
    hits = res["hits"]["hits"]
    docs.extend(hits)
    while hits:
        res = es_client.scroll(scroll_id=sid, scroll="2m")
        hits = res["hits"]["hits"]
        docs.extend(hits)
    try:
        es_client.clear_scroll(scroll_id=sid)
    except Exception:
        pass
    return docs


def _accumulate_breakdown(src, key, counter):
    for item in (src.get(key) or []):
        if item.get('label') and item.get('value') is not None:
            counter[item['label']] += int(item['value'])


def aggregate_metadata_docs(docs):
    """Aggregate totals from a list of pcap-metadata hits."""
    totals = {'packets': 0, 'connections': 0, 'bytes': 0, 'duration': 0.0}
    infected_hosts = set()
    transport = Counter()
    application = Counter()
    direction = Counter()
    dns = Counter()
    url = Counter()

    for hit in docs:
        src = hit["_source"]
        for field, key in [('total_packets', 'packets'), ('total_connections', 'connections'),
                            ('total_bytes', 'bytes')]:
            if src.get(field) is not None:
                totals[key] += int(src[field])
        if src.get('duration_seconds') is not None:
            totals['duration'] += float(src['duration_seconds'])
        if is_valid_infected_host(src.get('infected_host')):
            infected_hosts.add(str(src['infected_host']).strip())
        _accumulate_breakdown(src, 'transport_breakdown', transport)
        _accumulate_breakdown(src, 'application_breakdown', application)
        _accumulate_breakdown(src, 'direction_breakdown', direction)
        _accumulate_breakdown(src, 'top_dns_domains', dns)
        _accumulate_breakdown(src, 'top_url_domains', url)

    return totals, infected_hosts, transport, application, direction, dns, url


def scroll_global_ssl_totals(es_client):
    """Return a Counter of SSL domain totals across all pcap-dns docs."""
    ssl_totals = Counter()
    try:
        for hit in _scroll_docs(es_client, 'pcap-dns', ["domains"]):
            for d in hit["_source"].get("domains", []):
                if d.get("type") == "ssl" and d.get("domain") and d.get("count") is not None:
                    ssl_totals[d["domain"]] += int(d["count"])
    except Exception:
        pass
    return ssl_totals


def scroll_global_ip_sets(es_client, ips_index):
    """Return (unique_internal_ips, unique_external_ips) sets across all pcap-ips docs."""
    internal, external = set(), set()
    try:
        for hit in _scroll_docs(es_client, ips_index, ["internal_ips.ip", "external_ips.ip"]):
            src = hit["_source"]
            internal.update(ip["ip"] for ip in src.get("internal_ips", []) if ip.get("ip"))
            external.update(ip["ip"] for ip in src.get("external_ips", []) if ip.get("ip"))
    except Exception:
        pass
    return internal, external


def build_global_overview_response(es_client, elastic_module):
    """Assemble the global overview response dict across all PCAPs."""
    docs = _scroll_docs(es_client, elastic_module.PCAP_METADATA_INDEX, [
        "total_packets", "total_connections", "total_bytes",
        "duration_seconds", "infected_host",
        "transport_breakdown", "application_breakdown", "direction_breakdown",
        "top_dns_domains", "top_url_domains"
    ])
    totals, infected_hosts, transport, application, direction, dns, url = aggregate_metadata_docs(docs)
    ssl_totals = scroll_global_ssl_totals(es_client)
    unique_internal, unique_external = scroll_global_ip_sets(es_client, elastic_module.PCAP_IPS_INDEX)
    ftp_count = get_global_ftp_sessions(es_client)

    def sorted_items(counter, limit=None):
        items = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        return items[:limit] if limit else items

    return {
        'capture_summary': {
            'total_pcaps': len(docs),
            'pcap_packets': totals['packets'],
            'connections': totals['connections'],
            'bytes': totals['bytes'],
            'duration_seconds': round(totals['duration'], 2),
            'infected_hosts_count': len(infected_hosts),
            'internal_ip_count': len(unique_internal),
            'external_ip_count': len(unique_external),
            'ftp_sessions_count': ftp_count,
        },
        'traffic_distribution': {
            'transport':      [{'label': k, 'value': v} for k, v in sorted_items(transport)],
            'application':    [{'label': k, 'value': v} for k, v in sorted_items(application)],
            'direction':      [{'label': k, 'value': v} for k, v in sorted_items(direction)],
            'dns_domains':    [{'domain': k, 'count': v} for k, v in sorted_items(dns, 10)],
            'url_domains':    [{'domain': k, 'count': v} for k, v in sorted_items(url, 10)],
            'top_ssl_domains': [{'label': k, 'value': v} for k, v in sorted_items(ssl_totals, 10)],
        },
    }


def scroll_country_aggregation(es_client, ips_index):
    """Scroll pcap-ips and return per-country IP count, packet count, and capture set."""
    country_data = Counter()
    country_packets = Counter()
    country_captures = defaultdict(set)
    for hit in _scroll_docs(es_client, ips_index, ["external_ips", "pcap_id"]):
        pcap_id = hit["_source"].get("pcap_id")
        for ip_entry in hit["_source"].get("external_ips", []):
            country = ip_entry.get("country")
            if not country:
                continue
            country_data[country] += 1
            country_packets[country] += ip_entry.get("packet_count", 0)
            if pcap_id:
                country_captures[country].add(pcap_id)
    return country_data, country_packets, country_captures
