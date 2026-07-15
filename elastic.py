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

SCRIPTED_METRIC_INIT_SCRIPT = "state.map = [:]"
SCRIPTED_METRIC_COMBINE_SCRIPT = "return state.map"
SCRIPTED_METRIC_REDUCE_SCRIPT = (
    "def out = [:]; for (s in states) { for (e in s.entrySet()) { "
    "out[e.getKey()] = (out.containsKey(e.getKey()) ? out[e.getKey()] : 0) + e.getValue(); "
    "} } return out"
)

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
                "proxy_type":     {"type": "keyword"},
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

    from aggregations import load_zeek_ips, classify_ip_records

    actions = []

    # 1. Summary Record
    summary_data['pcap_id'] = pcap_id
    summary_data['pcap_filename'] = pcap_filename
    summary_data['analysis_timestamp'] = datetime.now(timezone.utc).isoformat()
    actions.append({"_index": PCAP_METADATA_INDEX, "_id": pcap_id, "_source": summary_data})

    # 2. IP Records
    internal_ips, external_ips = classify_ip_records(ips_data, load_zeek_ips(pcap_id))
    actions.append({
        "_index": PCAP_IPS_INDEX,
        "_id": pcap_id,
        "_source": {"pcap_id": pcap_id, "external_ips": external_ips, "internal_ips": internal_ips},
    })

    # 3. DNS
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

    from aggregations import normalise_file_log

    seen = {}
    for log in (files_logs or []):
        record = normalise_file_log(log)
        if record['filename'] not in seen or record['file_size'] > seen[record['filename']]['file_size']:
            seen[record['filename']] = record

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

# ---------------- SEARCH & AGGREGATIONS ----------------



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
                    "repository_size": {"sum": {"field": "total_bytes"}},
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

    from aggregations import aggregate_geo_from_external_ips, aggregate_geo_from_es

    if pcap_id:
        try:
            external_ips = es.get(index=PCAP_IPS_INDEX, id=pcap_id)["_source"].get("external_ips", [])
            if not external_ips:
                return {"isps": [], "countries": [], "cities": []}
            return aggregate_geo_from_external_ips(external_ips)
        except Exception as e:
            print(f"get_ip_breakdown (pcap) error: {e}")
            return {"isps": [], "countries": [], "cities": []}

    try:
        return aggregate_geo_from_es(es, PCAP_IPS_INDEX)
    except Exception as e:
        import traceback
        print(f"get_ip_breakdown (global) error: {e}")
        traceback.print_exc()
        return {"isps": [], "countries": [], "cities": []}


def get_report_details(report_type, value):
    """
    Returns a detailed list of unique IPs for a specific ISP, City, or Country.
    Queries ip-intelligence index where geo fields are stored flat.
    """
    import urllib.parse
    from aggregations import build_matched_ips, enrich_packet_counts, sort_ip_rows

    es = get_es()
    if not es: return []

    if '%' in value:
        value = urllib.parse.unquote(value)

    field_map = {'isp': 'geo.isp', 'country': 'geo.country'}
    field = field_map.get(report_type.lower())
    if not field: return []

    try:
        res = es.search(index=IP_INTEL_INDEX, body={
            "size": 10000,
            "query": {"bool": {"should": [
                {"term": {f"{field}.keyword": value}},
                {"match_phrase": {field: value}}
            ], "minimum_should_match": 1}}
        })
        print(f"DEBUG: Query {field}='{value}', hits={res['hits']['total']['value']}")
        matched_ips = build_matched_ips(res["hits"]["hits"])
        print(f"DEBUG: Found {len(matched_ips)} IPs from ip-intelligence")
        if matched_ips:
            try:
                enrich_packet_counts(es, PCAP_IPS_INDEX, matched_ips, res["hits"]["hits"])
            except Exception as e:
                import traceback
                print(f"DEBUG: Packet count lookup failed (non-critical): {e}")
                traceback.print_exc()
        return sort_ip_rows(matched_ips.values())
    except Exception as e:
        import traceback
        print(f"get_report_details error: {e}")
        traceback.print_exc()
        return []

def get_pcap_report_details(pcap_id, report_type, value):
    """
    Returns IP intelligence for IPs in a PCAP filtered by isp/country.
    Gets IP list from pcap-ips, then joins with ip-intelligence via mget.
    """
    import urllib.parse
    from aggregations import filter_ips_by_field, sort_ip_rows

    es = get_es()
    if not es: return []

    if '%' in value:
        value = urllib.parse.unquote(value)

    field = {'isp': 'isp', 'country': 'country'}.get(report_type.lower())
    if not field: return []

    try:
        external_ips = es.get(index=PCAP_IPS_INDEX, id=pcap_id)["_source"].get("external_ips", [])
        filtered = filter_ips_by_field(external_ips, field, value)
        if not filtered:
            return []

        # Build packet_count lookup from pcap-ips
        packet_map = {e['ip']: e.get('packet_count', 0) for e in filtered if e.get('ip')}

        # Join with ip-intelligence via mget
        intel_map = {}
        mget_res = es.mget(index=IP_INTEL_INDEX, body={"ids": list(packet_map.keys())})
        for doc in mget_res['docs']:
            if doc.get('found'):
                src = doc['_source']
                intel_map[src.get('ip')] = src

        # Merge: prefer intel record, fall back to pcap-ips data, always attach packet_count
        rows = []
        for entry in filtered:
            ip = entry.get('ip')
            if not ip:
                continue
            intel = intel_map.get(ip)
            if intel:
                row = dict(intel)
                # Preserve pcap-ips top-level coords as fallback when intel has none
                if row.get('latitude') is None and entry.get('latitude') is not None:
                    row['latitude'] = entry['latitude']
                if row.get('longitude') is None and entry.get('longitude') is not None:
                    row['longitude'] = entry['longitude']
                # Also check nested geo in intel
                geo = row.get('geo') or {}
                if row.get('latitude') is None:
                    row['latitude'] = geo.get('latitude') or geo.get('lat')
                if row.get('longitude') is None:
                    row['longitude'] = geo.get('longitude') or geo.get('lon')
            else:
                row = dict(entry)
            row['packet_count'] = packet_map.get(ip, 0)
            rows.append(row)

        return sort_ip_rows(rows)
    except Exception as e:
        print(f"get_pcap_report_details error: {e}")
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
    from aggregations import prepare_ip_intel_action, run_parallel_bulk

    es = get_es()
    if not es or not scan_records:
        return 0, []

    actions = [a for a in (prepare_ip_intel_action(r, IP_INTEL_INDEX) for r in scan_records) if a]
    if not actions:
        return 0, []

    try:
        success, errors = run_parallel_bulk(es, actions)
        if errors:
            print(f"  {len(errors)} IP intel record(s) failed bulk indexing")
        return success, errors
    except Exception as e:
        print(f"Bulk IP intel indexing error: {e}")
        return 0, [str(e)]
        return 0, [str(e)]


def get_external_ips_for_pcap(pcap_id):
    es = get_es()
    if not es: return []
    try:
        doc = es.get(index=PCAP_IPS_INDEX, id=pcap_id)
        return doc["_source"].get("external_ips", [])
    except Exception:
        return []


def get_internal_ips_for_pcap(pcap_id):
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
                "role":         {"type": "keyword"},
                "submitted_at": {"type": "date"},
            }
        }
    })
    print("\u2713 Created Index: feedback")


def index_feedback(name, email, organisation, message, role="user"):
    es = get_es()
    if not es:
        return None
    create_feedback_index()
    doc = {
        "name":         name,
        "email":        email,
        "organisation": organisation,
        "message":      message,
        "role":         role,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    return es.index(index=FEEDBACK_INDEX, document=doc)



def _recent_log_total(es, pcap_id):
    if pcap_id:
        meta = es.get(index=PCAP_METADATA_INDEX, id=pcap_id)["_source"]
        return int(meta.get("total_connections", 0) or 0)

    res = es.search(
        index=PCAP_METADATA_INDEX,
        body={"query": {"match_all": {}}, "size": 0, "aggs": {"total": {"sum": {"field": "total_connections"}}}},
    )
    return int(res.get("aggregations", {}).get("total", {}).get("value", 0) or 0)


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


def _format_recent_log(log):
    formatted = {}
    for key, value in log.items():
        if key == 'ts':
            # ts is now an ISO string (e.g. "2023-12-07T15:11:56.804497+00:00")
            try:
                formatted['timestamp'] = datetime.fromisoformat(str(value)).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                try:
                    formatted['timestamp'] = datetime.fromtimestamp(float(value), timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    formatted['timestamp'] = value
        elif key in ('id.orig_h', 'orig_h'):
            formatted['src_ip'] = value
        elif key in ('id.resp_h', 'resp_h'):
            formatted['dest_ip'] = value
        elif key in ('id.resp_p', 'resp_p'):
            formatted['resp_port'] = value
        elif key == 'conn_state':
            formatted['conn_state'] = value
            formatted['conn_state_desc'] = _CONN_STATE_MAP.get(str(value).upper(), value)
        elif key == 'duration':
            try:
                formatted[key] = f"{float(value):.6f}"
            except (ValueError, TypeError):
                formatted[key] = value
        else:
            formatted[key] = value
    return formatted


def _load_recent_logs_from_zeek_conn(es, pcap_id, start, per_page):
    if pcap_id:
        doc = es.get(index="zeek-conn", id=pcap_id)["_source"]
        all_conns = doc.get("connections", [])
    else:
        res = es.search(index="zeek-conn", body={"query": {"match_all": {}}, "size": 1000, "_source": ["connections"]})
        all_conns = []
        for hit in res["hits"]["hits"]:
            all_conns.extend(hit["_source"].get("connections") or [])
        all_conns.sort(key=lambda row: str(row.get("ts") or ""), reverse=True)

    return [_format_recent_log(row) for row in all_conns[start:start + per_page]]


def get_recent_logs_from_es(pcap_id=None, per_page=50, page=1):
    """Paginate connections from zeek-conn embedded array in Elasticsearch."""
    es = get_es()
    if not es:
        return {"logs": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 0}

    start = (page - 1) * per_page

    try:
        total = _recent_log_total(es, pcap_id)
    except Exception:
        total = 0

    total_pages = math.ceil(total / per_page) if per_page > 0 else 0
    logs = _load_recent_logs_from_zeek_conn(es, pcap_id, start, per_page)
    return {"logs": logs, "total": total, "page": page, "per_page": per_page, "total_pages": total_pages}


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


def get_time_series(pcap_id=None):
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
    if pcap_id:
        return get_ip_breakdown(pcap_id)
    try:
        countries, cities, isps = _get_intel_ip_counts()
        if not countries and not cities and not isps:
            return get_ip_breakdown(None)
        countries_list = [{"name": k, "count": v} for k, v in sorted(countries.items(), key=lambda x: x[1], reverse=True)]
        cities_list = [{"name": k, "count": v} for k, v in sorted(cities.items(), key=lambda x: x[1], reverse=True)]
        isps_list = [{"name": k, "count": v} for k, v in sorted(isps.items(), key=lambda x: x[1], reverse=True)]
        return {"countries": countries_list, "cities": cities_list, "isps": isps_list}
    except Exception as e:
        print(f"get_geo_aggregation error: {e}")
        return {"countries": [], "isps": [], "cities": []}


def _metric_map(agg):
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


def _to_items(values, label_key="label"):
    return [{label_key: k, "value": int(v)} for k, v in sorted((values or {}).items(), key=lambda x: x[1], reverse=True)]


def _apply_metadata_aggs(es, stats):
    """Run pcap-metadata aggregation and update stats in-place."""
    res = es.search(index=PCAP_METADATA_INDEX, body={
        "size": 0,
        "aggs": {
            "total_bytes": {"sum": {"field": "total_bytes"}},
            "total_packets": {"sum": {"field": "total_packets"}},
            "total_connections": {"sum": {"field": "total_connections"}},
            "total_file_size": {"sum": {"field": "file_size"}},
            "total_duration": {"sum": {"field": "duration_seconds"}},
            "transport_breakdown": {"scripted_metric": {
                "init_script": SCRIPTED_METRIC_INIT_SCRIPT,
                "map_script": "if (params._source.transport_breakdown != null) { for (item in params._source.transport_breakdown) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map[item.label] = (state.map.containsKey(item.label) ? state.map[item.label] : 0) + v; } } }",
                "combine_script": SCRIPTED_METRIC_COMBINE_SCRIPT,
                "reduce_script": SCRIPTED_METRIC_REDUCE_SCRIPT
            }},
            "application_breakdown": {"scripted_metric": {
                "init_script": SCRIPTED_METRIC_INIT_SCRIPT,
                "map_script": "if (params._source.application_breakdown != null) { for (item in params._source.application_breakdown) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map[item.label] = (state.map.containsKey(item.label) ? state.map[item.label] : 0) + v; } } }",
                "combine_script": SCRIPTED_METRIC_COMBINE_SCRIPT,
                "reduce_script": SCRIPTED_METRIC_REDUCE_SCRIPT
            }},
            "direction_breakdown": {"scripted_metric": {
                "init_script": SCRIPTED_METRIC_INIT_SCRIPT,
                "map_script": "if (params._source.direction_breakdown != null) { for (item in params._source.direction_breakdown) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map[item.label] = (state.map.containsKey(item.label) ? state.map[item.label] : 0) + v; } } }",
                "combine_script": SCRIPTED_METRIC_COMBINE_SCRIPT,
                "reduce_script": SCRIPTED_METRIC_REDUCE_SCRIPT
            }},
            "top_dns_domains": {"scripted_metric": {
                "init_script": SCRIPTED_METRIC_INIT_SCRIPT,
                "map_script": "if (params._source.top_dns_domains != null) { for (item in params._source.top_dns_domains) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map[item.label] = (state.map.containsKey(item.label) ? state.map[item.label] : 0) + v; } } }",
                "combine_script": SCRIPTED_METRIC_COMBINE_SCRIPT,
                "reduce_script": SCRIPTED_METRIC_REDUCE_SCRIPT
            }},
            "top_url_domains": {"scripted_metric": {
                "init_script": SCRIPTED_METRIC_INIT_SCRIPT,
                "map_script": "if (params._source.top_url_domains != null) { for (item in params._source.top_url_domains) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map[item.label] = (state.map.containsKey(item.label) ? state.map[item.label] : 0) + v; } } }",
                "combine_script": SCRIPTED_METRIC_COMBINE_SCRIPT,
                "reduce_script": SCRIPTED_METRIC_REDUCE_SCRIPT
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
    transport_vals = _metric_map(aggs.get("transport_breakdown", {}))
    application_vals = _metric_map(aggs.get("application_breakdown", {}))
    direction_vals = _metric_map(aggs.get("direction_breakdown", {}))
    dns_vals = _metric_map(aggs.get("top_dns_domains", {}))
    url_vals = _metric_map(aggs.get("top_url_domains", {}))
    infected_vals = aggs.get("infected_hosts", {}).get("value") if isinstance(aggs.get("infected_hosts", {}), dict) else []
    stats["transport_breakdown"] = _to_items(transport_vals)
    stats["application_breakdown"] = _to_items(application_vals)
    stats["direction_breakdown"] = _to_items(direction_vals)
    stats["top_dns_domains"] = _to_items(dns_vals)
    stats["top_url_domains"] = _to_items(url_vals)
    stats["infected_hosts"] = sorted(infected_vals or [])
    stats["infected_hosts_count"] = len(stats["infected_hosts"])
    stats["total_infected_hosts"] = stats["infected_hosts_count"]
    stats["total_protocols"] = len(transport_vals)
    stats["protocol_breakdown"] = [{"protocol": k, "count": v} for k, v in sorted(transport_vals.items(), key=lambda x: x[1], reverse=True)[:10]]
    stats["total_dns_domains"] = len(dns_vals)
    stats["total_url_domains"] = len(url_vals)


def _apply_ip_aggs(es, stats):
    """Run pcap-ips aggregation and update stats in-place."""
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
        for ip, packets in sorted(external_map.items(), key=lambda x: x[1], reverse=True)[:10]
    ]


def _apply_ssl_aggs(es, stats):
    """Run pcap-dns SSL aggregation and update stats in-place."""
    res = es.search(index=PCAP_DNS_INDEX, body={
        "size": 0,
        "aggs": {
            "ssl_domains": {
                "scripted_metric": {
                    "init_script": SCRIPTED_METRIC_INIT_SCRIPT,
                    "map_script": "if (params._source.domains != null) { for (item in params._source.domains) { if (item.type == 'ssl' && item.domain != null) { def key = item.domain.toString(); def count = item.count == null ? 0 : item.count; state.map[key] = (state.map.containsKey(key) ? state.map[key] : 0) + count; } } }",
                    "combine_script": SCRIPTED_METRIC_COMBINE_SCRIPT,
                    "reduce_script": SCRIPTED_METRIC_REDUCE_SCRIPT
                }
            }
        }
    })
    ssl_map = res.get("aggregations", {}).get("ssl_domains", {}).get("value", {})
    ssl_domains_list = [{"label": k, "value": int(v)} for k, v in (ssl_map or {}).items()]
    ssl_domains_list.sort(key=lambda x: x["value"], reverse=True)
    stats["top_ssl_domains"] = ssl_domains_list[:10]


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

    stats = dict(empty)
    try:
        stats["total_pcaps"] = int(es.count(index=PCAP_METADATA_INDEX, body={"query": {"match_all": {}}}).get("count", 0))
    except Exception:
        pass
    try:
        _apply_metadata_aggs(es, stats)
    except Exception as e:
        print(f"get_global_aggregation_fast error: {e}")
    try:
        _apply_ip_aggs(es, stats)
    except Exception as e:
        print(f"get_global_aggregation_fast IP error: {e}")
    try:
        _apply_ssl_aggs(es, stats)
    except Exception as e:
        print(f"get_global_aggregation_fast SSL error: {e}")
    return stats


