from elastic import get_es, PCAP_METADATA_INDEX, PCAP_IPS_INDEX, IP_INTEL_INDEX
from collections import defaultdict


def get_dashboard_breakdown_totals(pcap_id=None):
    """
    Aggregate transport, application, and direction breakdowns.
    Sums values from all PCAP metadata documents.
    """
    es = get_es()
    if not es:
        return {
            "transport_breakdown": [],
            "application_breakdown": [],
            "direction_breakdown": []
        }

    try:
        # Use Elasticsearch scripted_metric aggs to sum label/value pairings
        body = {
            "size": 0,
            "aggs": {
                "transport": {
                    "scripted_metric": {
                        "init_script": "state.map = [:]",
                        "map_script": "if (params._source.transport_breakdown != null) { for (item in params._source.transport_breakdown) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map.put(item.label, (state.map.containsKey(item.label) ? state.map.get(item.label) : 0) + v) } } }",
                        "combine_script": "return state.map",
                        "reduce_script": "def out = [:]; for (s in states) { for (e in s.entrySet()) { out.put(e.getKey(), out.getOrDefault(e.getKey(), 0) + e.getValue()); } } return out"
                    }
                },
                "application": {
                    "scripted_metric": {
                        "init_script": "state.map = [:]",
                        "map_script": "if (params._source.application_breakdown != null) { for (item in params._source.application_breakdown) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map.put(item.label, (state.map.containsKey(item.label) ? state.map.get(item.label) : 0) + v) } } }",
                        "combine_script": "return state.map",
                        "reduce_script": "def out = [:]; for (s in states) { for (e in s.entrySet()) { out.put(e.getKey(), out.getOrDefault(e.getKey(), 0) + e.getValue()); } } return out"
                    }
                },
                "direction": {
                    "scripted_metric": {
                        "init_script": "state.map = [:]",
                        "map_script": "if (params._source.direction_breakdown != null) { for (item in params._source.direction_breakdown) { if (item?.label != null) { def v = item.value == null ? 0 : item.value; state.map.put(item.label, (state.map.containsKey(item.label) ? state.map.get(item.label) : 0) + v) } } }",
                        "combine_script": "return state.map",
                        "reduce_script": "def out = [:]; for (s in states) { for (e in s.entrySet()) { out.put(e.getKey(), out.getOrDefault(e.getKey(), 0) + e.getValue()); } } return out"
                    }
                }
            }
        }

        res = es.search(index=PCAP_METADATA_INDEX, body=body)
        aggs = res.get('aggregations', {})

        def _map_to_list(m):
            return [{"label": k, "value": int(v)} for k, v in sorted((m or {}).items(), key=lambda x: x[1], reverse=True)]

        transport_vals = aggs.get('transport', {}).get('value') if isinstance(aggs.get('transport', {}), dict) and 'value' in aggs.get('transport', {}) else aggs.get('transport', {})
        application_vals = aggs.get('application', {}).get('value') if isinstance(aggs.get('application', {}), dict) and 'value' in aggs.get('application', {}) else aggs.get('application', {})
        direction_vals = aggs.get('direction', {}).get('value') if isinstance(aggs.get('direction', {}), dict) and 'value' in aggs.get('direction', {}) else aggs.get('direction', {})

        # scripted_metric returns the map directly; ensure dict
        if isinstance(transport_vals, dict) and 'map' in transport_vals:
            transport_vals = transport_vals.get('map')

        return {
            "transport_breakdown": _map_to_list(transport_vals or {}),
            "application_breakdown": _map_to_list(application_vals or {}),
            "direction_breakdown": _map_to_list(direction_vals or {}),
        }
    except Exception as e:
        print(f"get_dashboard_breakdown_totals error: {e}")
        return {
            "transport_breakdown": [],
            "application_breakdown": [],
            "direction_breakdown": []
        }


def get_country_city_map(pcap_id=None, limit=100):
    """
    Aggregate external IPs by country and city for map visualization.
    Returns list of locations with IP counts and coordinates from IP_INTEL_INDEX.
    """
    es = get_es()
    if not es:
        return []

    try:
        # Aggregate country -> city counts with a top_hits to retrieve coordinates
        body = {
            "size": 0,
            "aggs": {
                "by_country": {
                    "terms": {"field": "geo.country.keyword", "size": 1000},
                    "aggs": {
                        "by_city": {
                            "terms": {"field": "geo.city.keyword", "size": 1000, "missing": "Unknown"},
                            "aggs": {
                                "sample_geo": {"top_hits": {"_source": ["ip", "geo.latitude", "geo.longitude"], "size": 1}}
                            }
                        }
                    }
                }
            }
        }

        res = es.search(index=IP_INTEL_INDEX, body=body)
        aggs = res.get('aggregations', {})

        locations = []
        for country_bucket in aggs.get('by_country', {}).get('buckets', []):
            country = country_bucket.get('key')
            if not country or str(country).strip() == 'Unknown':
                continue
            for city_bucket in country_bucket.get('by_city', {}).get('buckets', []):
                city = city_bucket.get('key') or 'Unknown'
                ip_count = int(city_bucket.get('doc_count', 0))
                top_hit = city_bucket.get('sample_geo', {}).get('hits', {}).get('hits', [])
                lat = None
                lon = None
                if top_hit:
                    src = top_hit[0].get('_source', {})
                    geo = src.get('geo') or {}
                    lat = geo.get('latitude') or geo.get('lat')
                    lon = geo.get('longitude') or geo.get('lon')
                if lat is not None and lon is not None:
                    locations.append({
                        'country': country,
                        'city': city,
                        'latitude': lat,
                        'longitude': lon,
                        'ip_count': ip_count
                    })

        locations.sort(key=lambda x: x['ip_count'], reverse=True)
        return locations[:limit]
    except Exception as e:
        print(f"get_country_city_map error: {e}")
        return []


def get_all_external_ips(pcap_id=None, limit=10000):
    """
    Retrieve all external IPs with their enrichment data from IP_INTEL_INDEX.
    Returns detailed IP records with WHOIS, geo, ports, etc.
    """
    es = get_es()
    if not es:
        return []

    try:
        # Use scrolling for large result sets to avoid ES size limits and memory spikes
        if limit <= 10000:
            res = es.search(
                index=IP_INTEL_INDEX,
                body={
                    "query": {"match_all": {}},
                    "size": limit,
                    "_source": [
                        "ip", "rdns", "asn", "geo", "whois", "dnsbl",
                        "os_info", "hostnames", "ports", "scan_time"
                    ]
                }
            )
            return [hit.get("_source", {}) for hit in res.get("hits", {}).get("hits", [])]

        # limit > 10000 -> use scroll
        rows = []
        scroll_resp = es.search(
            index=IP_INTEL_INDEX,
            body={"query": {"match_all": {}}, "_source": [
                "ip", "rdns", "asn", "geo", "whois", "dnsbl",
                "os_info", "hostnames", "ports", "scan_time"
            ]},
            size=10000,
            scroll="2m"
        )
        sid = scroll_resp.get("_scroll_id")
        while True:
            hits = scroll_resp.get("hits", {}).get("hits", [])
            if not hits:
                break
            for h in hits:
                rows.append(h.get("_source", {}))
                if len(rows) >= limit:
                    break
            if len(rows) >= limit:
                break
            scroll_resp = es.scroll(scroll_id=sid, scroll="2m")

        try:
            if sid:
                es.clear_scroll(scroll_id=sid)
        except Exception:
            pass

        return rows
    except Exception as e:
        print(f"get_all_external_ips error: {e}")
        return []