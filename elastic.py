import os
import json
import math
from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError
from elasticsearch.helpers import bulk, parallel_bulk
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ---------------- CONFIG ----------------

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_API_KEY = os.getenv("ES_API_KEY")
ES_USER = os.getenv("ELASTIC_USER")
ES_PASSWORD = os.getenv("ELASTIC_PASSWORD")

# Granular Indexes
PCAP_METADATA_INDEX = "pcap-metadata"  # Full PCAP metadata (superset of captures + dashboard)
PCAP_IPS_INDEX = "pcap-ips"            # Granular per-pcap IP rows (packet counts, geo)
PCAP_DNS_INDEX = "pcap-dns"            # Granular DNS/URL records
PCAP_FILES_INDEX = "pcap-files"        # File transfer records
IP_INTEL_INDEX = "ip-intelligence"     # One record per unique IP ΓÇö WHOIS, ports, DNSBL, OS
ZEEK_CONN_INDEX = "zeek-conn"          # Cached Zeek conn.log summaries and connection logs

# ---------------- CONNECTION ----------------
_es_instance = None

def get_es():
    global _es_instance
    if _es_instance is not None:
        return _es_instance

    try:
        auth = None
        if ES_API_KEY:
            auth = {"api_key": ES_API_KEY}
        elif ES_USER and ES_PASSWORD:
            auth = (ES_USER, ES_PASSWORD)
        # Allow connection without authentication for localhost

        es = Elasticsearch(
            ES_HOST,
            basic_auth=auth if isinstance(auth, tuple) else None,
            api_key=auth["api_key"] if isinstance(auth, dict) else None,
            verify_certs=False,
            request_timeout=60,
            max_retries=3,
            retry_on_timeout=True,
            connections_per_node=5,
            http_compress=True,
        )

        if es.ping():
            _es_instance = es
            print(f"Connected to Elasticsearch at {ES_HOST}")
        else:
            print(f"Cannot ping Elasticsearch at {ES_HOST}")
            _es_instance = None
    except Exception as e:
        print(f"ES connection error: {e}")
        _es_instance = None

    return _es_instance

# ---------------- INDEX CREATION ----------------
def create_granular_indexes():
    es = get_es()
    if not es: return

    dashboard_mapping = {
        "mappings": {
            "properties": {
                "pcap_id":               {"type": "keyword"},
                "file_id":               {"type": "keyword"},
                "file_name":             {"type": "keyword"},
                "pcap_filename":         {"type": "keyword"},
                "analysis_timestamp":    {"type": "date"},
                "start_time_utc":        {"type": "date"},
                "end_time_utc":          {"type": "date"},
                "duration_seconds":      {"type": "double"},
                "attack_duration_seconds": {"type": "double"},
                "file_size":             {"type": "long"},
                "total_packets":         {"type": "long"},
                "exact_pcap_packets":    {"type": "long"},
                "total_connections":     {"type": "long"},
                "total_dns_queries":     {"type": "long"},
                "total_http_requests":   {"type": "long"},
                "total_bytes":           {"type": "long"},
                "unique_sources":        {"type": "long"},
                "malware_type":          {"type": "keyword"},
                "infected_host":         {"type": "keyword"},
                "reputation_status":     {"type": "keyword"},
                "transport_breakdown": {"properties": {
                    "label": {"type": "keyword"},
                    "value": {"type": "long"}
                }},
                "application_breakdown": {"properties": {
                    "label": {"type": "keyword"},
                    "value": {"type": "long"}
                }},
                "direction_breakdown": {"properties": {
                    "label": {"type": "keyword"},
                    "value": {"type": "long"}
                }},
                "time_series": {"properties": {
                    "label": {"type": "date"},
                    "value": {"type": "long"}
                }},
                "top_dns_domains": {"properties": {
                    "label": {"type": "keyword"},
                    "value": {"type": "long"}
                }},
                "top_url_domains": {"properties": {
                    "label": {"type": "keyword"},
                    "value": {"type": "long"}
                }},
                "protocols": {"properties": {
                    "protocol": {"type": "keyword"},
                    "packet_count": {"type": "long"}
                }},
                "ports": {"properties": {
                    "port": {"type": "keyword"},
                    "protocol": {"type": "keyword"},
                    "usage": {"type": "long"}
                }},
                "user_agents": {"properties": {
                    "user_agent": {"type": "keyword"}
                }},
                "ftp_session": {"properties": {
                    "source_ip":       {"type": "keyword"},
                    "destination_ip":  {"type": "keyword"},
                    "port":            {"type": "keyword"},
                    "username":        {"type": "keyword"},
                    "command":         {"type": "keyword"},
                    "file_transferred":{"type": "keyword"},
                    "data_type":       {"type": "keyword"}
                }},
            },
            "dynamic": False
        }
    }

    # 2. GRANULAR IPS
    ips_mapping = {
        "mappings": {
            "properties": {
                "pcap_id":                   {"type": "keyword"},
                "external_ips": {
                    "type": "nested",
                    "properties": {
                        "ip":                        {"type": "ip"},
                        "packet_count":              {"type": "integer"},
                        "country":                   {"type": "keyword"},
                        "city":                      {"type": "keyword"},
                        "isp":                       {"type": "keyword"},
                        "latitude":                  {"type": "double"},
                        "longitude":                 {"type": "double"},
                        "location":                  {"type": "geo_point"},
                        "is_internal":               {"type": "boolean"},
                        "internal_connection_count": {"type": "integer"}
                    }
                },
                "internal_ips": {
                    "type": "nested",
                    "properties": {
                        "ip":                        {"type": "ip"},
                        "packet_count":              {"type": "integer"},
                        "country":                   {"type": "keyword"},
                        "city":                      {"type": "keyword"},
                        "isp":                       {"type": "keyword"},
                        "latitude":                  {"type": "double"},
                        "longitude":                 {"type": "double"},
                        "location":                  {"type": "geo_point"},
                        "is_internal":               {"type": "boolean"},
                        "internal_connection_count": {"type": "integer"}
                    }
                }
            }
        }
    }

    # 3. GRANULAR DNS/URLS
    dns_mapping = {
        "mappings": {
            "properties": {
                "pcap_id": {"type": "keyword"},
                "record_type": {"type": "keyword"},
                "pcap_filename": {"type": "keyword"},
                "analysis_timestamp": {"type": "date"},
                "domain_count": {"type": "integer"},
                "domains": {
                    "type": "nested",
                    "properties": {
                        "domain": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "record_type": {"type": "keyword"},
                        "count": {"type": "integer"},
                        "is_ioc": {"type": "boolean"}
                    }
                }
            }
        }
    }

    files_mapping = {
        "mappings": {
            "properties": {
                "pcap_id": {"type": "keyword"},
                "filename": {"type": "keyword"},
                "type": {"type": "keyword"},
                "protocol": {"type": "keyword"},
                "file_size": {"type": "long"}
            }
        }
    }

    intel_mapping = {
        "mappings": {
            "properties": {
                "ip":             {"type": "ip"},
                "scan_time":      {"type": "date"},
                "enriched_at":    {"type": "date"},
                "last_seen":      {"type": "date"},
                "source":         {"type": "keyword"},
                "status":         {"type": "keyword"},
                "rdns":           {"type": "keyword"},
                "asn":            {"type": "keyword"},
                "location":       {"type": "geo_point"},
                "geo": {"properties": {
                    "country":   {"type": "keyword"},
                    "city":      {"type": "keyword"},
                    "isp":       {"type": "keyword"},
                    "latitude":  {"type": "double"},
                    "longitude": {"type": "double"},
                }},
                "whois": {"properties": {
                    "org":           {"type": "keyword"},
                    "name":          {"type": "keyword"},
                    "cidr":          {"type": "keyword"},
                    "network_owner": {"type": "keyword"},
                    "registered":    {"type": "keyword"},
                    "registrar":     {"type": "keyword"},
                    "website":       {"type": "keyword"},
                    "tld":           {"type": "keyword"},
                    "email":         {"type": "keyword"},
                    "phone":         {"type": "keyword"},
                    "address":       {"type": "text"},
                }},
                "dnsbl": {"properties": {
                    "listed":         {"type": "boolean"},
                    "total_listings": {"type": "integer"},
                }},
                "os_info": {"properties": {
                    "best_match":  {"type": "keyword"},
                    "confidence": {"type": "float"},
                    "reliable":   {"type": "boolean"},
                }},
                "hostnames": {"type": "keyword"},
                "ports": {"properties": {
                    "port":     {"type": "integer"},
                    "protocol": {"type": "keyword"},
                    "service":  {"type": "keyword"},
                    "state":    {"type": "keyword"},
                }},
            },
            "dynamic": True,
        }
    }

    conn_logs_mapping = {
        "mappings": {
            "properties": {
                "pcap_id":    {"type": "keyword"},
                "ts":         {"type": "double"},
                "id.orig_h":  {"type": "ip"},
                "id.resp_h":  {"type": "ip"},
                "id.resp_p":  {"type": "integer"},
                "proto":      {"type": "keyword"},
                "service":    {"type": "keyword"},
                "duration":   {"type": "double"},
                "orig_bytes": {"type": "long"},
                "conn_state": {"type": "keyword"},
            }
        }
    }

    for idx, mapping in [
        (PCAP_METADATA_INDEX, dashboard_mapping),
        (PCAP_IPS_INDEX, ips_mapping),
        (PCAP_DNS_INDEX, dns_mapping),
        (PCAP_FILES_INDEX, files_mapping),
        (IP_INTEL_INDEX, intel_mapping),
        (ZEEK_CONN_INDEX, conn_logs_mapping),
    ]:
        if not es.indices.exists(index=idx):
            es.indices.create(index=idx, body=mapping)
            print(f"Created Index: {idx}")

# ---------------- INDEXING ----------------

def bulk_index_granular_data(pcap_id, pcap_filename, summary_data, ips_data, dns_data):
    es = get_es()
    if not es: return

    actions = []

    # 1. Summary Record ΓÇö one doc per pcap_id
    summary_data['pcap_id'] = pcap_id
    summary_data['pcap_filename'] = pcap_filename
    summary_data['analysis_timestamp'] = datetime.now(timezone.utc).isoformat()
    actions.append({
        "_index": PCAP_METADATA_INDEX,
        "_id": pcap_id,
        "_source": summary_data
    })

    # 2. IP Records — one doc per pcap_id, IPs embedded as arrays
    # Prefer Zeek conn.log to determine TCP/UDP internal IPs when available.
    zeek_folder = os.getenv('ZEEK_LOGS_FOLDER', 'zeek_logs')
    zeek_ips = None
    log_path = os.path.join(zeek_folder, pcap_id, 'conn.log')
    if os.path.exists(log_path):
        try:
            from zeek_parser import get_internal_tcp_udp_ip_aggregation_from_conn_log
            stats = get_internal_tcp_udp_ip_aggregation_from_conn_log(log_path)
            zeek_ips = set(stats.get('ips', []))
        except Exception:
            zeek_ips = None

    external_ips = []
    internal_ips = []
    for ip_record in (ips_data or []):
        lat = ip_record.get('latitude')
        lon = ip_record.get('longitude')
        if lat is not None and lon is not None:
            ip_record['location'] = {"lat": lat, "lon": lon}

        ip_addr = ip_record.get('ip')
        proto = str(ip_record.get('proto') or '').lower()

        # If Zeek conn.log is available, use it as ground-truth for internal IPs
        if zeek_ips is not None:
            if ip_addr in zeek_ips:
                internal_ips.append(ip_record)
            else:
                external_ips.append(ip_record)
        else:
            # Fall back to existing flag-based logic but ensure only TCP/UDP counted as internal
            if ip_record.get('is_internal') and proto in ('tcp', 'udp'):
                internal_ips.append(ip_record)
            else:
                external_ips.append(ip_record)

    actions.append({
        "_index": PCAP_IPS_INDEX,
        "_id": pcap_id,
        "_source": {
            "pcap_id": pcap_id,
            "external_ips": external_ips,
            "internal_ips": internal_ips,
        }
    })

    # 3. DNS ΓÇö one doc per pcap_id, domains embedded as array
    actions.append({
        "_index": PCAP_DNS_INDEX,
        "_id": pcap_id,
        "_source": {
            "pcap_id": pcap_id,
            "record_type": "capture_summary",
            "pcap_filename": pcap_filename,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": summary_data,
            "domain_count": len(dns_data or []),
            "domains": [
                {k: v for k, v in d.items() if k not in ("pcap_id",)}
                for d in (dns_data or [])
            ],
        }
    })

    try:
        success, errors = bulk(es, actions, raise_on_error=False)
        if errors:
            print(f"  {len(errors)} records failed to index for {pcap_id}")
        return success
    except Exception as e:
        print(f"Bulk indexing error: {e}")
        return 0


def index_pcap_files(pcap_id, files_logs):
    """Index file records as a single doc per pcap_id with files embedded as array."""
    es = get_es()
    if not es:
        return 0

    seen = {}
    for log in (files_logs or []):
        filename = log.get('filename') or log.get('fuid') or 'unknown'
        if filename in ('-', '', None):
            filename = log.get('fuid') or 'unknown'
        mime_type = log.get('mime_type') or log.get('mimetype') or 'unknown'
        source = log.get('source') or 'unknown'
        try:
            raw = log.get('total_bytes') or log.get('seen_bytes') or 0
            size = round(int(raw if raw not in ('-', '', None) else 0) / 1000, 2)
        except (ValueError, TypeError):
            size = 0

        if filename not in seen or size > seen[filename]['file_size']:
            seen[filename] = {
                'filename': filename,
                'type': mime_type if mime_type not in ('-', '') else 'unknown',
                'protocol': source.upper() if source not in ('-', '') else 'unknown',
                'file_size': size,
            }

    try:
        es.index(
            index=PCAP_FILES_INDEX,
            id=pcap_id,
            document={"pcap_id": pcap_id, "files": list(seen.values()), "file_count": len(seen)}
        )
        return len(seen)
    except Exception as e:
        print(f"pcap-files indexing error: {e}")
        return 0


def index_dashboard_document(pcap_id, dashboard_data):
    es = get_es()
    if not es:
        return None

    payload = dict(dashboard_data)
    payload["file_id"] = pcap_id
    payload["pcap_id"] = pcap_id
    payload["analysis_timestamp"] = datetime.now(timezone.utc).isoformat()

    try:
        return es.index(index=PCAP_METADATA_INDEX, id=pcap_id, document=payload)
    except TypeError:
        return es.index(index=PCAP_METADATA_INDEX, id=pcap_id, body=payload)
    except Exception as e:
        print(f"Dashboard index error for {pcap_id}: {e}")
        return None


def get_dashboard_document(pcap_id):
    es = get_es()
    if not es:
        return None

    try:
        doc = es.get(index=PCAP_METADATA_INDEX, id=pcap_id)["_source"]
        if doc.get("file_id") == pcap_id or doc.get("pcap_id") == pcap_id:
            return doc
    except NotFoundError:
        pass
    except Exception:
        pass

    try:
        res = es.search(
            index=PCAP_METADATA_INDEX,
            body={"query": {"term": {"file_id": pcap_id}}},
            size=1,
        )
        hits = res.get("hits", {}).get("hits", [])
        if hits:
            doc = hits[0].get("_source", {})
            if doc.get("file_id") == pcap_id or doc.get("pcap_id") == pcap_id:
                return doc
    except Exception:
        pass

    return None


def get_latest_dashboard_document():
    es = get_es()
    if not es:
        return None

    try:
        res = es.search(
            index=PCAP_METADATA_INDEX,
            body={"query": {"match_all": {}}},
            size=1,
            sort=[{"analysis_timestamp": {"order": "desc"}}]
        )
        hits = res.get("hits", {}).get("hits", [])
        if hits:
            return hits[0].get("_source")
        return None
    except Exception:
        return None

# (Legacy support for index_pcap_analysis)
def index_pcap_analysis(pcap_id, pcap_filename, external_ips, **kwargs):
    pass

# ---------------- SEARCH & AGGREGATIONS ----------------

def get_pcap_stats_from_es(pcap_id):
    es = get_es()
    if not es: return None

    summary = get_pcap_summary(pcap_id)
    if not summary:
        return None

    # All aggregated breakdowns are stored in pcap-metadata and zeek-conn sentinel
    try:
        sentinel = es.get(index="zeek-conn", id=pcap_id)["_source"]
    except Exception:
        sentinel = {}

    trans_stats = summary.get("transport_breakdown") or sentinel.get("transport_breakdown", [])
    app_stats   = summary.get("application_breakdown") or sentinel.get("application_breakdown", [])
    dir_stats   = summary.get("direction_breakdown") or sentinel.get("direction_breakdown", [])
    ports       = summary.get("ports") or sentinel.get("ports", [])
    time_series = sentinel.get("time_series", [])

    # DNS stats from pcap-dns embedded domains
    dns_stats = []
    try:
        dns_doc = es.get(index=PCAP_DNS_INDEX, id=pcap_id)["_source"]
        dns_domains = [
            d for d in (dns_doc.get("domains") or []) if d.get("type") == "dns"
        ]
        dns_domains.sort(key=lambda d: d.get("count", 0), reverse=True)
        dns_stats = [{"label": d["domain"], "value": d.get("count", 0)} for d in dns_domains[:10]]
    except Exception:
        pass

    ext_ips = get_external_ips_for_pcap(pcap_id)

    dns_records = []
    try:
        dns_doc = es.get(index=PCAP_DNS_INDEX, id=pcap_id)["_source"]
        for d in (dns_doc.get("domains") or [])[:100]:
            dns_records.append({
                "domain": d.get("domain"),
                "record_type": d.get("record_type"),
                "timestamp": dns_doc.get("analysis_timestamp")
            })
    except Exception:
        pass

    protocols = [{"protocol": s["label"], "packet_count": s["value"]} for s in trans_stats]

    return {
        'file_id': pcap_id,
        'file_name': summary.get('pcap_filename'),
        'total_packets': summary.get('total_packets', 0),
        'total_bytes': summary.get('total_bytes', 0),
        'duration_seconds': summary.get('duration_seconds', 0),
        'file_size': summary.get('file_size', 0),
        'total_connections': sentinel.get('total_connections', sum(s['value'] for s in trans_stats)),
        'exact_pcap_packets': summary.get('total_packets'),
        'transport_breakdown': trans_stats,
        'application_breakdown': app_stats,
        'direction_breakdown': dir_stats,
        'top_dns_domains': dns_stats,
        'top_destinations': [],
        'external_ips': ext_ips,
        'internal_ips': get_internal_ips_for_pcap(pcap_id),
        'dns_queries': dns_records,
        'protocols': protocols,
        'ports': ports,
        'time_series': time_series,
        'summary': summary
    }


def get_all_pcap_summaries():
    es = get_es()
    if not es: return []
    try:
        res = es.search(
            index=PCAP_METADATA_INDEX,
            body={"query": {"match_all": {}}},
            size=1000,
            sort=[{"analysis_timestamp": {"order": "desc"}}]
        )
        return [hit["_source"] for hit in res["hits"]["hits"]]
    except Exception:
        return []

def get_pcap_summary(pcap_id):
    es = get_es()
    if not es: return None
    try:
        return es.get(index=PCAP_METADATA_INDEX, id=pcap_id)["_source"]
    except NotFoundError:
        return None


def get_repository_stats():
    es = get_es()
    if not es:
        return {
            "total_pcaps": 0,
            "observed_ips": 0,
            "repository_size": 0,
            "traffic_volume": 0,
        }

    try:
        total_pcaps = int(es.count(index=PCAP_METADATA_INDEX, body={"query": {"match_all": {}}}).get("count", 0))
    except Exception:
        total_pcaps = 0

    try:
        capture_agg = es.search(
            index=PCAP_METADATA_INDEX,
            body={
                "query": {"match_all": {}},
                "size": 0,
                "aggs": {
                    "repository_size": {"sum": {"field": "file_size"}},
                    "traffic_volume": {"sum": {"field": "total_packets"}},
                },
            },
        )
        aggs = capture_agg.get("aggregations", {})
        repository_size = int(aggs.get("repository_size", {}).get("value", 0) or 0)
        traffic_volume = int(aggs.get("traffic_volume", {}).get("value", 0) or 0)
    except Exception:
        repository_size = 0
        traffic_volume = 0

    try:
        observed_ips = int(es.count(index=IP_INTEL_INDEX, body={"query": {"match_all": {}}}).get("count", 0))
    except Exception:
        observed_ips = 0

    return {
        "total_pcaps": total_pcaps,
        "observed_ips": observed_ips,
        "repository_size": repository_size,
        "traffic_volume": traffic_volume,
    }

def get_global_aggregation():
    return get_global_aggregation_fast()


def _get_intel_ip_counts():
    """Returns {country: count}, {city: count}, {isp: count} from ip-intelligence."""
    es = get_es()
    if not es:
        return {}, {}, {}
    try:
        res = es.search(index=IP_INTEL_INDEX, body={
            "size": 0,
            "aggs": {
                "by_country": {"terms": {"field": "geo.country.keyword", "size": 10000}},
                "by_city":    {"terms": {"field": "geo.city.keyword",    "size": 10000}},
                "by_isp":     {"terms": {"field": "geo.isp.keyword",     "size": 10000}},
            }
        })
        aggs = res.get("aggregations", {})
        countries = {b["key"]: b["doc_count"] for b in aggs.get("by_country", {}).get("buckets", [])}
        cities    = {b["key"]: b["doc_count"] for b in aggs.get("by_city",    {}).get("buckets", [])}
        isps      = {b["key"]: b["doc_count"] for b in aggs.get("by_isp",     {}).get("buckets", [])}
        return countries, cities, isps
    except Exception:
        return {}, {}, {}


def get_ip_breakdown(pcap_id=None):
    es = get_es()
    if not es: return {"isps": [], "countries": [], "cities": []}

    # If filtering by pcap, aggregate directly from pcap-ips nested data
    if pcap_id:
        try:
            doc = es.get(index=PCAP_IPS_INDEX, id=pcap_id)["_source"]
            external_ips = doc.get("external_ips", [])
            
            if not external_ips:
                return {"isps": [], "countries": [], "cities": []}
            
            # Aggregate in-memory from the nested array
            from collections import defaultdict
            countries = defaultdict(lambda: {"count": 0, "packets": 0})
            cities = defaultdict(lambda: {"count": 0, "packets": 0})
            isps = defaultdict(lambda: {"count": 0, "packets": 0})
            
            for ip_entry in external_ips:
                country = ip_entry.get("country")
                city = ip_entry.get("city")
                isp = ip_entry.get("isp")
                packets = ip_entry.get("packet_count", 0)

                if country:
                    countries[country]["count"] += 1
                    countries[country]["packets"] += packets
                if city:
                    cities[city]["count"] += 1
                    cities[city]["packets"] += packets
                if isp:
                    isps[isp]["count"] += 1
                    isps[isp]["packets"] += packets

            return {
                "countries": sorted([{"name": k, "packets": v["packets"], "ip_count": v["count"]} for k, v in countries.items()], key=lambda x: x["ip_count"], reverse=True),
                "cities":    sorted([{"name": k, "packets": v["packets"], "ip_count": v["count"]} for k, v in cities.items()],    key=lambda x: x["ip_count"], reverse=True),
                "isps":      sorted([{"name": k, "packets": v["packets"], "ip_count": v["count"]} for k, v in isps.items()],      key=lambda x: x["ip_count"], reverse=True)
            }
        except Exception as e:
            print(f"get_ip_breakdown (pcap) error: {e}")
            return {"isps": [], "countries": [], "cities": []}
    
    # Global aggregation from pcap-ips nested external_ips data
    try:
        res = es.search(
            index=PCAP_IPS_INDEX,
            body={
                "size": 0,
                "aggs": {
                    "geo_stats": {
                        "scripted_metric": {
                            "init_script": "state.countries = [:]; state.cities = [:]; state.isps = [:]",
                            "map_script": """
                            if (params._source.external_ips != null) {
                                for (item in params._source.external_ips) {
                                    def country = item.country;
                                    def city = item.city;
                                    def isp = item.isp;
                                    def packets = item.packet_count == null ? 0 : item.packet_count;
                                    
                                    if (country != null) {
                                        def countryKey = country.toString();
                                        if (!state.countries.containsKey(countryKey)) {
                                            state.countries[countryKey] = ['count': 0, 'packets': 0];
                                        }
                                        state.countries[countryKey].count += 1;
                                        state.countries[countryKey].packets += packets;
                                    }
                                    if (city != null) {
                                        def cityKey = city.toString();
                                        if (!state.cities.containsKey(cityKey)) {
                                            state.cities[cityKey] = ['count': 0, 'packets': 0];
                                        }
                                        state.cities[cityKey].count += 1;
                                        state.cities[cityKey].packets += packets;
                                    }
                                    if (isp != null) {
                                        def ispKey = isp.toString();
                                        if (!state.isps.containsKey(ispKey)) {
                                            state.isps[ispKey] = ['count': 0, 'packets': 0];
                                        }
                                        state.isps[ispKey].count += 1;
                                        state.isps[ispKey].packets += packets;
                                    }
                                }
                            }
                            """,
                            "combine_script": "return ['countries': state.countries, 'cities': state.cities, 'isps': state.isps]",
                            "reduce_script": """
                            def result = ['countries': [:], 'cities': [:], 'isps': [:]];
                            for (s in states) {
                                for (entry in s.countries.entrySet()) {
                                    if (!result.countries.containsKey(entry.key)) {
                                        result.countries[entry.key] = ['count': 0, 'packets': 0];
                                    }
                                    result.countries[entry.key].count += entry.value.count;
                                    result.countries[entry.key].packets += entry.value.packets;
                                }
                                for (entry in s.cities.entrySet()) {
                                    if (!result.cities.containsKey(entry.key)) {
                                        result.cities[entry.key] = ['count': 0, 'packets': 0];
                                    }
                                    result.cities[entry.key].count += entry.value.count;
                                    result.cities[entry.key].packets += entry.value.packets;
                                }
                                for (entry in s.isps.entrySet()) {
                                    if (!result.isps.containsKey(entry.key)) {
                                        result.isps[entry.key] = ['count': 0, 'packets': 0];
                                    }
                                    result.isps[entry.key].count += entry.value.count;
                                    result.isps[entry.key].packets += entry.value.packets;
                                }
                            }
                            return result;
                            """
                        }
                    }
                }
            }
        )
        
        aggs_result = res.get("aggregations", {}).get("geo_stats", {}).get("value", {})
        
        countries = [{"name": k, "count": v["count"], "packets": v["packets"]} for k, v in (aggs_result.get("countries") or {}).items()]
        cities = [{"name": k, "count": v["count"], "packets": v["packets"]} for k, v in (aggs_result.get("cities") or {}).items()]
        isps = [{"name": k, "count": v["count"], "packets": v["packets"]} for k, v in (aggs_result.get("isps") or {}).items()]
        
        return {
            "countries": sorted(countries, key=lambda x: x["count"], reverse=True),
            "cities": sorted(cities, key=lambda x: x["count"], reverse=True),
            "isps": sorted(isps, key=lambda x: x["count"], reverse=True)
        }
    except Exception as e:
        print(f"get_ip_breakdown (global) error: {e}")
        import traceback
        traceback.print_exc()
        return {"isps": [], "countries": [], "cities": []}

def get_report_details(report_type, value):
    """
    Returns a detailed list of unique IPs for a specific ISP, City, or Country.
    Queries ip-intelligence index where geo fields are stored flat.
    """
    import urllib.parse
    
    es = get_es()
    if not es: return []

    # Ensure value is properly URL decoded
    if '%' in value:
        value = urllib.parse.unquote(value)
    
    field_map = {'isp': 'geo.isp', 'city': 'geo.city', 'country': 'geo.country'}
    field = field_map.get(report_type.lower())
    if not field: return []

    try:
        # Try both exact match and case-insensitive match
        res = es.search(index=IP_INTEL_INDEX, body={
            "size": 10000,
            "query": {
                "bool": {
                    "should": [
                        {"term": {f"{field}.keyword": value}},
                        {"match_phrase": {field: value}}
                    ],
                    "minimum_should_match": 1
                }
            },
            "_source": ["ip", "geo", "asn", "pcap_id"]
        })
        
        print(f"DEBUG: Query {field}='{value}', hits={res['hits']['total']['value']}")

        matched_ips = {}
        for h in res["hits"]["hits"]:
            src = h["_source"]
            geo = src.get("geo") or {}
            ip = src.get("ip")
            matched_ips[ip] = {
                "ip":        ip,
                "packets":   0,
                "isp":       geo.get("isp") or "Unknown",
                "city":      geo.get("city") or "Unknown",
                "country":   geo.get("country") or "Unknown",
                "latitude":  geo.get("latitude"),
                "longitude": geo.get("longitude"),
            }
        
        print(f"DEBUG: Found {len(matched_ips)} IPs from ip-intelligence")

        if matched_ips:
            try:
                pcap_ids = sorted({
                    h["_source"].get("pcap_id")
                    for h in res["hits"]["hits"]
                    if h.get("_source", {}).get("pcap_id")
                })
                target_ips = set(matched_ips.keys())

                for start in range(0, len(pcap_ids), 500):
                    batch = pcap_ids[start:start + 500]
                    mget_res = es.mget(
                        index=PCAP_IPS_INDEX,
                        body={"ids": batch},
                        _source=["external_ips"]
                    )

                    for doc in mget_res.get("docs", []):
                        if not doc.get("found"):
                            continue
                        for ip_entry in (doc.get("_source", {}).get("external_ips") or []):
                            ip = ip_entry.get("ip")
                            if ip in target_ips:
                                matched_ips[ip]["packets"] += int(ip_entry.get("packet_count") or 0)

            except Exception as e:
                print(f"DEBUG: Packet count lookup failed (non-critical): {e}")
                import traceback
                traceback.print_exc()
                # Continue without packet counts - this is not critical

        return sorted(
            matched_ips.values(),
            key=lambda row: (
                0 if (row.get("packets") or 0) > 0 else 1,
                -(row.get("packets") or 0),
                str(row.get("ip") or "")
            )
        )
    except Exception as e:
        print(f"get_report_details error: {e}")
        import traceback
        traceback.print_exc()
        return []


def get_pcap_report_details(pcap_id, report_type, value):
    """
    Returns a detailed list of IPs for a specific ISP, City, or Country within a single PCAP.
    Uses pcap-ips index and returns same structure as get_report_details but scoped to one PCAP.
    """
    import urllib.parse
    
    es = get_es()
    if not es: return []

    # Ensure value is properly URL decoded
    if '%' in value:
        value = urllib.parse.unquote(value)

    field_map = {'isp': 'isp', 'city': 'city', 'country': 'country'}
    field = field_map.get(report_type.lower())
    if not field: return []

    try:
        # Get the specific PCAP's IP data
        doc = es.get(index=PCAP_IPS_INDEX, id=pcap_id)
        external_ips = doc["_source"].get("external_ips", [])
        
        # Filter IPs that match the report criteria (exact match, case-insensitive)
        matched_ips = []
        for ip_entry in external_ips:
            ip_field_value = ip_entry.get(field)
            # Check for exact match or case-insensitive match
            if (ip_field_value == value or 
                (ip_field_value and value and ip_field_value.lower() == value.lower())):
                matched_ips.append({
                    "ip":        ip_entry.get("ip"),
                    "packets":   ip_entry.get("packet_count", 0),
                    "isp":       ip_entry.get("isp") or "Unknown",
                    "city":      ip_entry.get("city") or "Unknown",
                    "country":   ip_entry.get("country") or "Unknown",
                    "latitude":  ip_entry.get("latitude"),
                    "longitude": ip_entry.get("longitude"),
                })
        
        return sorted(
            matched_ips,
            key=lambda row: (
                0 if (row.get("packets") or 0) > 0 else 1,
                -(row.get("packets") or 0),
                str(row.get("ip") or "")
            )
        )
    except Exception as e:
        print(f"get_pcap_report_details error: {e}")
        return []

def get_dns_breakdown(pcap_id=None):
    es = get_es()
    if not es: return []

    query = {"match_all": {}}
    if pcap_id: query = {"term": {"pcap_id": pcap_id}}

    aggs = {
        "domains": {
            "terms": {"field": "domain", "size": 100},
            "aggs": {"count": {"sum": {"field": "count"}}}
        }
    }

    try:
        res = es.search(index=PCAP_DNS_INDEX, body={"query": query, "aggs": aggs, "size": 0})
        buckets = res.get("aggregations", {}).get("domains", {}).get("buckets", [])
        return [{b["key"]: int(b.get("count", {}).get("value", 0))} for b in buckets]
    except Exception:
        return []

# IP intelligence helpers (stored in IP_INTEL_INDEX ΓÇö one record per unique IP)
def index_ip_scan(scan_data):
    es = get_es()
    if not es: return None
    ip = scan_data.get("ip")
    if not ip:
        return None

    record = dict(scan_data)
    record["intelligence_record"] = True
    geo = record.get("geo") or {}
    lat = geo.get("latitude") if geo.get("latitude") is not None else geo.get("lat")
    lon = geo.get("longitude") if geo.get("longitude") is not None else geo.get("lon")
    if lat is not None and lon is not None:
        record["location"] = {"lat": lat, "lon": lon}

    try:
        return es.index(index=IP_INTEL_INDEX, id=ip, body=record)
    except Exception:
        return None


def bulk_index_ip_scans(scan_records):
    """
    Bulk-upsert into IP_INTEL_INDEX. _id = ip so each IP has exactly one record.
    Returns (success_count, error_list).
    """
    es = get_es()
    if not es or not scan_records:
        return 0, []

    actions = []
    for record in scan_records:
        ip = record.get("ip")
        if not ip:
            continue
        doc = dict(record)
        doc["intelligence_record"] = True
        geo = doc.get("geo") or {}
        lat = geo.get("latitude") if geo.get("latitude") is not None else geo.get("lat")
        lon = geo.get("longitude") if geo.get("longitude") is not None else geo.get("lon")
        if lat is not None and lon is not None:
            doc["location"] = {"lat": lat, "lon": lon}
        actions.append({
            "_op_type": "index",
            "_index": IP_INTEL_INDEX,
            "_id": ip,          # one record per IP, no duplicates
            "_source": doc,
        })

    if not actions:
        return 0, []

    try:
        success = 0
        errors = []
        for ok, item in parallel_bulk(
            es, actions,
            thread_count=8, chunk_size=1000,
            raise_on_error=False,
        ):
            if ok:
                success += 1
            else:
                errors.append(item)
        if errors:
            print(f"  {len(errors)} IP intel record(s) failed bulk indexing")
        return success, errors
    except Exception as e:
        print(f"Bulk IP intel indexing error: {e}")
        return 0, [str(e)]


def get_external_ips_for_pcap(pcap_id):
    es = get_es()
    if not es: return []
    try:
        doc = es.get(index=PCAP_IPS_INDEX, id=pcap_id)
        return doc["_source"].get("external_ips", [])
    except Exception:
        return []


def get_internal_ips_for_pcap(pcap_id, zeek_logs_folder=None):
    es = get_es()
    if not es:
        return []
    try:
        doc = es.get(index=PCAP_IPS_INDEX, id=pcap_id)
        return doc["_source"].get("internal_ips", [])
    except Exception:
        return []


def get_dns_queries_for_pcap(pcap_id, limit=200):
    """Read domains from the embedded array in the single pcap-dns doc."""
    es = get_es()
    if not es: return []
    try:
        doc = es.get(index=PCAP_DNS_INDEX, id=pcap_id)["_source"]
        domains = [
            d for d in (doc.get("domains") or [])
            if d.get("type") == "dns"
        ]
        domains.sort(key=lambda d: d.get("count", 0), reverse=True)
        return [
            {"domain": d.get("domain"), "record_type": d.get("record_type"), "count": d.get("count")}
            for d in domains[:limit]
        ]
    except Exception:
        return []


def get_ioc_domains_for_pcap(pcap_id, limit=200):
    """Read IOC domains from the embedded array in the single pcap-dns doc."""
    es = get_es()
    if not es: return []
    try:
        doc = es.get(index=PCAP_DNS_INDEX, id=pcap_id)["_source"]
        return [
            {"domain": d.get("domain"), "reason": d.get("reason", "Suspicious domain")}
            for d in (doc.get("domains") or [])
            if d.get("is_ioc")
        ][:limit]
    except Exception:
        return []


def get_ioc_urls_for_pcap(pcap_id, limit=200):
    """Read IOC URLs from the embedded array in the single pcap-dns doc."""
    es = get_es()
    if not es: return []
    try:
        doc = es.get(index=PCAP_DNS_INDEX, id=pcap_id)["_source"]
        return [
            {"url": d.get("domain"), "method": d.get("method", "GET"), "purpose": d.get("purpose", "HTTP activity")}
            for d in (doc.get("domains") or [])
            if d.get("type") == "http" and d.get("is_ioc")
        ][:limit]
    except Exception:
        return []


def get_ip_geo_from_pcap_ips(ip):
    """Fetch geo fields for an IP directly from pcap-ips as a fast fallback."""
    es = get_es()
    if not es:
        return {}
    try:
        res = es.search(index=PCAP_IPS_INDEX, body={
            "query": {"term": {"ip": ip}},
            "_source": ["country", "city", "isp", "asn", "latitude", "longitude"],
            "size": 1
        })
        hits = res.get("hits", {}).get("hits", [])
        if hits:
            src = hits[0]["_source"]
            return {
                "country": src.get("country"),
                "city": src.get("city"),
                "isp": src.get("isp"),
                "asn": src.get("asn"),
                "latitude": src.get("latitude"),
                "longitude": src.get("longitude"),
            }
    except Exception:
        pass
    return {}


def get_ip_scan(ip):
    es = get_es()
    if not es: return None
    try:
        doc = es.get(index=IP_INTEL_INDEX, id=ip)
        return doc.get("_source")
    except NotFoundError:
        return None
    except Exception:
        return None


FEEDBACK_INDEX = "feedback"


def create_feedback_index():
    es = get_es()
    if not es:
        return
    if es.indices.exists(index=FEEDBACK_INDEX):
        return
    es.indices.create(index=FEEDBACK_INDEX, body={
        "mappings": {
            "properties": {
                "name":         {"type": "keyword"},
                "email":        {"type": "keyword"},
                "organisation": {"type": "keyword"},
                "message":      {"type": "text"},
                "submitted_at": {"type": "date"},
            }
        }
    })
    print("\u2713 Created Index: feedback")


def index_feedback(name, email, organisation, message):
    es = get_es()
    if not es:
        return None
    create_feedback_index()
    doc = {
        "name":         name,
        "email":        email,
        "organisation": organisation,
        "message":      message,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    return es.index(index=FEEDBACK_INDEX, id=name, body=doc)


# ---------------- LEGACY COMPAT ----------------

def get_pcap_analysis(pcap_id):
    """Fetch a single PCAP summary from the captures index."""
    return get_pcap_summary(pcap_id)


def get_all_pcap_analyses():
    """Return all PCAP summaries sorted by timestamp."""
    return get_all_pcap_summaries()


def get_geo_grid_aggregation(precision=3):
    """
    Groups 50,000+ IPs into geographical clusters using Geo-Grid aggregation.
    Returns lat/lon centroids and counts for each cluster.
    """
    es = get_es()
    if not es:
        return []

    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"term": {"is_internal": False}}
                ],
                "must_not": [
                    {"term": {"latitude": 0}},
                    {"term": {"longitude": 0}}
                ]
            }
        },
        "aggs": {
            "grid": {
                "geohash_grid": {
                    "field": "location",
                    "precision": precision
                },
                "aggs": {
                    "centroid": {
                        "geo_centroid": {"field": "location"}
                    },
                    "unique_ips": {
                        "cardinality": {"field": "ip"}
                    }
                }
            }
        }
    }

    try:
        res = es.search(index=PCAP_IPS_INDEX, body=body)
        buckets = res.get("aggregations", {}).get("grid", {}).get("buckets", [])
        
        points = []
        for b in buckets:
            centroid = b.get("centroid", {}).get("location", {})
            unique_count = b.get("unique_ips", {}).get("value", 0)
            if centroid:
                points.append({
                    "lat": centroid.get("lat"),
                    "lon": centroid.get("lon"),
                    "count": int(unique_count),
                    "hits": b["doc_count"], # Keep original doc count as 'hits' if needed
                    "geohash": b["key"]
                })
        return points

    except Exception as e:
        print(f"Geo Grid Aggregation Error: {e}")
        return []


def get_recent_logs_from_es(log_type, timeline=None, page=1, per_page=50, pcap_id=None, zeek_logs_folder=None):
    """Paginate connections. First 500 from zeek-conn embedded array, beyond that from conn.log on disk."""
    es = get_es()
    if not es:
        return {"logs": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

    ES_CAP = 500
    start = (page - 1) * per_page

    # Always get the real total from the sentinel doc
    total = 0
    try:
        if pcap_id:
            sentinel = es.get(index="zeek-conn", id=pcap_id)["_source"]
            total = sentinel.get("total_connections", 0)
        else:
            res = es.search(index="zeek-conn", body={"query": {"match_all": {}}, "size": 0,
                            "aggs": {"total": {"sum": {"field": "total_connections"}}}})
            total = int(res.get("aggregations", {}).get("total", {}).get("value", 0))
    except Exception:
        pass

    total_pages = math.ceil(total / per_page) if per_page > 0 else 0

    def _format(log):
        conn_state_map = {
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
            'OTH': 'Midstream traffic only, no SYN observed'
        }
        
        f_log = {}
        for k, v in log.items():
            if k == 'ts':
                try:
                    f_log['timestamp'] = datetime.fromtimestamp(float(v), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    f_log['timestamp'] = v
            elif k in ('id.orig_h', 'orig_h'):
                f_log['src_ip'] = v
            elif k in ('id.resp_h', 'resp_h'):
                f_log['dest_ip'] = v
            elif k in ('id.resp_p', 'resp_p'):
                f_log['resp_port'] = v
            elif k == 'conn_state':
                f_log['conn_state_desc'] = conn_state_map.get(str(v).upper(), v)
            elif k == 'duration':
                try:
                    f_log[k] = f"{float(v):.6f}"
                except (ValueError, TypeError):
                    f_log[k] = v
            else:
                f_log[k] = v
        return f_log

    # Serve from zeek-conn embedded array if within the cached 500
    if start < ES_CAP:
        try:
            if pcap_id:
                doc = es.get(index="zeek-conn", id=pcap_id)["_source"]
                all_conns = doc.get("connections", [])
            else:
                res = es.search(index="zeek-conn", body={"query": {"match_all": {}},
                                "size": 1000, "_source": ["connections"]})
                all_conns = []
                for h in res["hits"]["hits"]:
                    all_conns.extend(h["_source"].get("connections") or [])
                all_conns.sort(key=lambda r: float(r.get("ts") or 0), reverse=True)
            page_logs = all_conns[start:start + per_page]
            return {"logs": [_format(r) for r in page_logs], "total": total, "page": page,
                    "per_page": per_page, "total_pages": total_pages}
        except Exception as e:
            raise e

    # Beyond ES cap ΓÇö stream from conn.log on disk
    if not zeek_logs_folder or not pcap_id:
        return {"logs": [], "total": total, "page": page,
                "per_page": per_page, "total_pages": total_pages}

    log_path = os.path.join(zeek_logs_folder, pcap_id, "conn.log")
    if not os.path.exists(log_path):
        return {"logs": [], "total": total, "page": page,
                "per_page": per_page, "total_pages": total_pages}

    try:
        from zeek_parser import parse_zeek_log
        all_logs = parse_zeek_log(log_path)
        all_logs.sort(key=lambda r: float(r.get('ts') or 0), reverse=True)
        page_logs = all_logs[start:start + per_page]
        return {"logs": [_format(r) for r in page_logs], "total": total, "page": page,
                "per_page": per_page, "total_pages": total_pages}
    except Exception as e:
        raise e


def get_pcap_files(pcap_id):
    """Fetch files from the single pcap-files doc for this pcap_id."""
    es = get_es()
    if not es:
        return []
    try:
        doc = es.get(index=PCAP_FILES_INDEX, id=pcap_id)
        return doc["_source"].get("files", [])
    except Exception:
        return []


def get_all_pcap_list(search="", page=1, per_page=12):
    """Get PCAPs from pcap-metadata with ES-side pagination."""
    es = get_es()
    if not es:
        return [], 0
    try:
        query = {"match_all": {}}
        if search:
            query = {"wildcard": {"pcap_filename": {"value": f"*{search}*", "case_insensitive": True}}}

        # Get total count
        count_res = es.count(index=PCAP_METADATA_INDEX, body={"query": query})
        total = count_res.get("count", 0)

        # Fetch only the page we need
        start = (page - 1) * per_page
        res = es.search(
            index=PCAP_METADATA_INDEX,
            body={
                "query": query,
                "_source": ["pcap_id", "pcap_filename", "file_name", "file_size", "summary", "total_packets", "duration_seconds", "unique_ips"],
                "sort": [{"analysis_timestamp": {"order": "desc"}}],
                "from": start,
                "size": per_page,
            }
        )
        results = []
        for hit in res["hits"]["hits"]:
            src = hit["_source"]
            filename = src.get("pcap_filename", src.get("file_name", ""))
            results.append({
                "pcap_id": src.get("pcap_id"),
                "filename": filename,
                "size": src.get("file_size") or src.get("summary", {}).get("file_size", 0),
                "packets": src.get("total_packets"),
                "duration": src.get("duration_seconds"),
                "ip_count": src.get("unique_ips", 0)
            })
        return results, total
    except Exception:
        return [], 0


def get_time_series(pcap_id=None, interval_seconds=30):
    """Return pre-aggregated time_series from the zeek-conn sentinel doc."""
    es = get_es()
    if not es:
        return []
    try:
        if pcap_id:
            doc = es.get(index="zeek-conn", id=pcap_id)["_source"]
            return doc.get("time_series", [])
        # Global: merge time_series from all sentinel docs
        res = es.search(index="zeek-conn", body={"query": {"match_all": {}}, "size": 1000,
                                                  "_source": ["time_series"]})
        from collections import defaultdict
        merged = defaultdict(int)
        for h in res["hits"]["hits"]:
            for point in (h["_source"].get("time_series") or []):
                merged[point["label"]] += point["value"]
        return [{"label": k, "value": v} for k, v in sorted(merged.items())]
    except Exception as e:
        print(f"time_series error: {e}")
        return []


def get_geo_aggregation(pcap_id=None):
    """Aggregate ISP/Country/City.
    For a specific `pcap_id` aggregate from the `pcap-ips` nested documents
    (authoritative per-capture data). For the global view (no `pcap_id`) prefer
    the flattened `ip-intelligence` index which contains enriched geo records.
    """
    es = get_es()
    if not es:
        return {"countries": [], "isps": [], "cities": []}

    # Per-PCAP: use pcap-ips nested aggregation
    if pcap_id:
        return get_ip_breakdown(pcap_id)

    # Global: prefer ip-intelligence counts (fast, enriched)
    try:
        countries, cities, isps = _get_intel_ip_counts()
        # If ip-intelligence has no data, fall back to aggregating from pcap-ips
        if not countries and not cities and not isps:
            return get_ip_breakdown(None)

        countries_list = [{"name": k, "count": v} for k, v in sorted(countries.items(), key=lambda x: x[1], reverse=True)]
        cities_list = [{"name": k, "count": v} for k, v in sorted(cities.items(), key=lambda x: x[1], reverse=True)]
        isps_list = [{"name": k, "count": v} for k, v in sorted(isps.items(), key=lambda x: x[1], reverse=True)]
        return {"countries": countries_list, "cities": cities_list, "isps": isps_list}
    except Exception as e:
        print(f"get_geo_aggregation error: {e}")
        return {"countries": [], "isps": [], "cities": []}


def get_global_aggregation_fast():
    """ES-native global aggregation used by dashboard and API routes."""
    es = get_es()
    empty = {
        "total_external_ips": 0,
        "total_internal_ips": 0,
        "total_bytes": 0,
        "total_packets": 0,
        "total_connections": 0,
        "total_file_size": 0,
        "total_duration": 0.0,
        "total_infected_hosts": 0,
        "infected_hosts": [],
        "infected_hosts_count": 0,
        "total_dns_domains": 0,
        "total_url_domains": 0,
        "total_protocols": 0,
        "total_pcaps": 0,
        "top_dns_domains": [],
        "top_url_domains": [],
        "top_ssl_domains": [],
        "top_active_ips": [],
        "transport_breakdown": [],
        "application_breakdown": [],
        "direction_breakdown": [],
        "protocol_breakdown": []
    }
    if not es:
        return empty

    def metric_map(agg):
        if not isinstance(agg, dict):
            return {}
        value = agg.get("value")
        if isinstance(value, dict):
            return value
        if isinstance(value, list):
            return {str(v): 1 for v in value}
        if isinstance(agg.get("map"), dict):
            return agg.get("map")
        return {}

    def to_items(values, label_key="label"):
        return [{label_key: key, "value": int(value)} for key, value in sorted((values or {}).items(), key=lambda item: item[1], reverse=True)]

    stats = dict(empty)

    try:
        stats["total_pcaps"] = int(es.count(index=PCAP_METADATA_INDEX, body={"query": {"match_all": {}}}).get("count", 0))
    except Exception:
        pass

    try:
        res = es.search(index=PCAP_METADATA_INDEX, body={
            "size": 0,
            "aggs": {
                "total_bytes": {"sum": {"field": "total_bytes"}},
                "total_packets": {"sum": {"field": "total_packets"}},
                "total_connections": {"sum": {"field": "total_connections"}},
                "total_file_size": {"sum": {"field": "file_size"}},
                "total_duration": {"sum": {"field": "duration_seconds"}},
                "transport_breakdown": {"scripted_metric": {
                    "init_script": "state.map = [:]",
                    "map_script": "if (params._source.transport_breakdown != null) { for (item in params._source.transport_breakdown) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map[item.label] = (state.map.containsKey(item.label) ? state.map[item.label] : 0) + v; } } }",
                    "combine_script": "return state.map",
                    "reduce_script": "def out = [:]; for (s in states) { for (e in s.entrySet()) { out[e.getKey()] = (out.containsKey(e.getKey()) ? out[e.getKey()] : 0) + e.getValue(); } } return out"
                }},
                "application_breakdown": {"scripted_metric": {
                    "init_script": "state.map = [:]",
                    "map_script": "if (params._source.application_breakdown != null) { for (item in params._source.application_breakdown) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map[item.label] = (state.map.containsKey(item.label) ? state.map[item.label] : 0) + v; } } }",
                    "combine_script": "return state.map",
                    "reduce_script": "def out = [:]; for (s in states) { for (e in s.entrySet()) { out[e.getKey()] = (out.containsKey(e.getKey()) ? out[e.getKey()] : 0) + e.getValue(); } } return out"
                }},
                "direction_breakdown": {"scripted_metric": {
                    "init_script": "state.map = [:]",
                    "map_script": "if (params._source.direction_breakdown != null) { for (item in params._source.direction_breakdown) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map[item.label] = (state.map.containsKey(item.label) ? state.map[item.label] : 0) + v; } } }",
                    "combine_script": "return state.map",
                    "reduce_script": "def out = [:]; for (s in states) { for (e in s.entrySet()) { out[e.getKey()] = (out.containsKey(e.getKey()) ? out[e.getKey()] : 0) + e.getValue(); } } return out"
                }},
                "top_dns_domains": {"scripted_metric": {
                    "init_script": "state.map = [:]",
                    "map_script": "if (params._source.top_dns_domains != null) { for (item in params._source.top_dns_domains) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map[item.label] = (state.map.containsKey(item.label) ? state.map[item.label] : 0) + v; } } }",
                    "combine_script": "return state.map",
                    "reduce_script": "def out = [:]; for (s in states) { for (e in s.entrySet()) { out[e.getKey()] = (out.containsKey(e.getKey()) ? out[e.getKey()] : 0) + e.getValue(); } } return out"
                }},
                "top_url_domains": {"scripted_metric": {
                    "init_script": "state.map = [:]",
                    "map_script": "if (params._source.top_url_domains != null) { for (item in params._source.top_url_domains) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map[item.label] = (state.map.containsKey(item.label) ? state.map[item.label] : 0) + v; } } }",
                    "combine_script": "return state.map",
                    "reduce_script": "def out = [:]; for (s in states) { for (e in s.entrySet()) { out[e.getKey()] = (out.containsKey(e.getKey()) ? out[e.getKey()] : 0) + e.getValue(); } } return out"
                }},
                "infected_hosts": {"scripted_metric": {
                    "init_script": "state.set = new HashSet()",
                    "map_script": "def infected = params._source.infected_host; if (infected != null) { infected = infected.toString().trim(); if (infected.length() > 0 && infected != 'Unknown' && infected != 'N/A' && infected != '-' && infected != 'None' && infected != 'null' && !infected.contains('::') && !infected.startsWith('231.') && !infected.startsWith('224.') && !infected.startsWith('239.')) { state.set.add(infected); } }",
                    "combine_script": "return state.set",
                    "reduce_script": "def out = new HashSet(); for (s in states) { out.addAll(s); } return out"
                }}
            }
        })
        aggs = res.get("aggregations", {})
        stats["total_bytes"] = int(aggs.get("total_bytes", {}).get("value", 0) or 0)
        stats["total_packets"] = int(aggs.get("total_packets", {}).get("value", 0) or 0)
        stats["total_connections"] = int(aggs.get("total_connections", {}).get("value", 0) or 0)
        stats["total_file_size"] = int(aggs.get("total_file_size", {}).get("value", 0) or 0)
        stats["total_duration"] = float(aggs.get("total_duration", {}).get("value", 0) or 0.0)

        transport_vals = metric_map(aggs.get("transport_breakdown", {}))
        application_vals = metric_map(aggs.get("application_breakdown", {}))
        direction_vals = metric_map(aggs.get("direction_breakdown", {}))
        dns_vals = metric_map(aggs.get("top_dns_domains", {}))
        url_vals = metric_map(aggs.get("top_url_domains", {}))
        infected_vals = aggs.get("infected_hosts", {}).get("value") if isinstance(aggs.get("infected_hosts", {}), dict) else []

        stats["transport_breakdown"] = to_items(transport_vals)
        stats["application_breakdown"] = to_items(application_vals)
        stats["direction_breakdown"] = to_items(direction_vals)
        stats["top_dns_domains"] = to_items(dns_vals)
        stats["top_url_domains"] = to_items(url_vals)
        stats["infected_hosts"] = sorted(list(infected_vals or []))
        stats["infected_hosts_count"] = len(stats["infected_hosts"])
        stats["total_infected_hosts"] = stats["infected_hosts_count"]
        stats["total_protocols"] = len(transport_vals)
        stats["protocol_breakdown"] = [{"protocol": k, "count": v} for k, v in sorted(transport_vals.items(), key=lambda item: item[1], reverse=True)[:10]]
        stats["total_dns_domains"] = len(dns_vals)
        stats["total_url_domains"] = len(url_vals)

    except Exception as e:
        print(f"get_global_aggregation_fast error: {e}")

    try:
        res = es.search(index=PCAP_IPS_INDEX, body={
            "size": 0,
            "aggs": {
                "ip_stats": {
                    "scripted_metric": {
                        "init_script": "state.external = [:]; state.internal = new HashSet()",
                        "map_script": "if (params._source.external_ips != null) { for (item in params._source.external_ips) { def ip = item.ip; if (ip != null) { def key = ip.toString(); def packets = item.packet_count == null ? 0 : item.packet_count; state.external[key] = (state.external.containsKey(key) ? state.external[key] : 0) + packets; } } } if (params._source.internal_ips != null) { for (item in params._source.internal_ips) { def ip = item.ip; if (ip != null) { state.internal.add(ip.toString()); } } }",
                        "combine_script": "return ['external': state.external, 'internal': state.internal]",
                        "reduce_script": "def external = [:]; def internal = new HashSet(); for (s in states) { for (e in s.external.entrySet()) { external[e.getKey()] = (external.containsKey(e.getKey()) ? external[e.getKey()] : 0) + e.getValue(); } internal.addAll(s.internal); } return ['external': external, 'internal': internal];"
                    }
                }
            }
        })
        ip_stats = res.get("aggregations", {}).get("ip_stats", {}).get("value", {})
        external_map = ip_stats.get("external", {}) if isinstance(ip_stats, dict) else {}
        internal_values = ip_stats.get("internal", []) if isinstance(ip_stats, dict) else []
        stats["total_external_ips"] = len(external_map)
        stats["total_internal_ips"] = len(set(internal_values))
        stats["top_active_ips"] = [
            {"ip": ip, "packets": int(packets)}
            for ip, packets in sorted(external_map.items(), key=lambda item: item[1], reverse=True)[:10]
        ]
    except Exception as e:
        print(f"get_global_aggregation_fast IP error: {e}")

    try:
        res = es.search(index=PCAP_DNS_INDEX, body={
            "size": 0,
            "aggs": {
                "ssl_domains": {
                    "scripted_metric": {
                        "init_script": "state.map = [:]",
                        "map_script": "if (params._source.domains != null) { for (item in params._source.domains) { if (item.type == 'ssl' && item.domain != null) { def key = item.domain.toString(); def count = item.count == null ? 0 : item.count; state.map[key] = (state.map.containsKey(key) ? state.map[key] : 0) + count; } } }",
                        "combine_script": "return state.map",
                        "reduce_script": "def out = [:]; for (s in states) { for (e in s.entrySet()) { out[e.getKey()] = (out.containsKey(e.getKey()) ? out[e.getKey()] : 0) + e.getValue(); } } return out"
                    }
                }
            }
        })
        ssl_map = res.get("aggregations", {}).get("ssl_domains", {}).get("value", {})
        ssl_domains_list = [{"label": k, "value": int(v)} for k, v in (ssl_map or {}).items()]
        ssl_domains_list.sort(key=lambda x: x["value"], reverse=True)
        stats["top_ssl_domains"] = ssl_domains_list[:10]
    except Exception as e:
        print(f"get_global_aggregation_fast SSL error: {e}")

    return stats


def get_global_country_aggregation_fast(limit=100):
    """ES-native aggregation for /api/map/external-ips."""
    es = get_es()
    if not es:
        return []

    try:
        res = es.search(index=PCAP_IPS_INDEX, body={
            "size": 0,
            "aggs": {
                "country_stats": {
                    "scripted_metric": {
                        "init_script": "state.map = [:]",
                        "map_script": "def pcapId = params._source.pcap_id; if (params._source.external_ips != null) { for (item in params._source.external_ips) { def country = item.country; if (country != null) { def key = country.toString(); def packets = item.packet_count == null ? 0 : item.packet_count; if (!state.map.containsKey(key)) { state.map[key] = ['count':0, 'packets':0, 'captures': new HashSet()]; } state.map[key].count += 1; state.map[key].packets += packets; if (pcapId != null) { state.map[key].captures.add(pcapId.toString()); } } } }",
                        "combine_script": "return state.map",
                        "reduce_script": "def out = [:]; for (s in states) { for (e in s.entrySet()) { if (!out.containsKey(e.getKey())) { out[e.getKey()] = ['count':0, 'packets':0, 'captures': new HashSet()]; } out[e.getKey()].count += e.getValue().count; out[e.getKey()].packets += e.getValue().packets; out[e.getKey()].captures.addAll(e.getValue().captures); } } return out;"
                    }
                }
            }
        })

        country_map = res.get("aggregations", {}).get("country_stats", {}).get("value", {})
        countries = []
        for country, data in (country_map or {}).items():
            if not country:
                continue
            countries.append({
                "name": country,
                "count": int(data.get("count", 0) or 0),
                "packets": int(data.get("packets", 0) or 0),
                "captures": len(set(data.get("captures", []) or [])),
            })

        countries.sort(key=lambda item: item["count"], reverse=True)
        return countries if limit is None else countries[:limit]
    except Exception as e:
        print(f"get_global_country_aggregation_fast error: {e}")
        return []
