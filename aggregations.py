from elastic import get_es, PCAP_METADATA_INDEX, PCAP_IPS_INDEX, IP_INTEL_INDEX
from collections import defaultdict

SCRIPTED_METRIC_INIT_MAP = "state.map = [:]"
SCRIPTED_METRIC_COMBINE_MAP = "return state.map"
SCRIPTED_METRIC_REDUCE_MAP = "def out = [:]; for (s in states) { for (e in s.entrySet()) { out.put(e.getKey(), out.getOrDefault(e.getKey(), 0) + e.getValue()); } } return out"



def get_country_city_map(limit=100):
    """
    Aggregate external IPs by country and city for map visualization.
    Returns list of locations with IP counts and coordinates from IP_INTEL_INDEX.
    """
    es = get_es()
    if not es:
        return []

    try:
        body = _build_country_city_map_body()
        res = es.search(index=IP_INTEL_INDEX, body=body)
        locations = _extract_country_city_locations(res.get('aggregations', {}))
        locations.sort(key=lambda x: x['ip_count'], reverse=True)
        return locations[:limit]
    except Exception as e:
        print(f"get_country_city_map error: {e}")
        return []


def _build_country_city_map_body():
    return {
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

def _extract_country_city_locations(aggs):
    locations = []
    for country_bucket in aggs.get('by_country', {}).get('buckets', []):
        country = country_bucket.get('key')
        if _should_skip_country(country):
            continue

        for city_bucket in country_bucket.get('by_city', {}).get('buckets', []):
            location = _country_city_location_from_bucket(country, city_bucket)
            if location is not None:
                locations.append(location)

    return locations


def _should_skip_country(country):
    return not country or str(country).strip() == 'Unknown'


def _country_city_location_from_bucket(country, city_bucket):
    lat, lon = _extract_coordinates(city_bucket)
    if lat is None or lon is None:
        return None

    return {
        'country': country,
        'city': city_bucket.get('key') or 'Unknown',
        'latitude': lat,
        'longitude': lon,
        'ip_count': int(city_bucket.get('doc_count', 0))
    }


def _extract_coordinates(city_bucket):
    top_hit = city_bucket.get('sample_geo', {}).get('hits', {}).get('hits', [])
    if not top_hit:
        return None, None

    src = top_hit[0].get('_source', {})
    geo = src.get('geo') or {}
    lat = geo.get('latitude') or geo.get('lat')
    lon = geo.get('longitude') or geo.get('lon')
    return lat, lon


def get_all_external_ips(limit=10000):
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



def aggregate_geo_from_external_ips(external_ips):
    """Aggregate country/city/isp counts from an in-memory list of IP records."""
    from collections import defaultdict
    countries = defaultdict(lambda: {"count": 0, "packets": 0})
    cities = defaultdict(lambda: {"count": 0, "packets": 0})
    isps = defaultdict(lambda: {"count": 0, "packets": 0})
    for ip_entry in external_ips:
        packets = ip_entry.get("packet_count", 0)
        for key, bucket in (
            (ip_entry.get("country"), countries),
            (ip_entry.get("city"), cities),
            (ip_entry.get("isp"), isps),
        ):
            if key:
                bucket[key]["count"] += 1
                bucket[key]["packets"] += packets
    return {
        "countries": sorted([{"name": k, "packets": v["packets"], "ip_count": v["count"]} for k, v in countries.items()], key=lambda x: x["ip_count"], reverse=True),
        "cities":    sorted([{"name": k, "packets": v["packets"], "ip_count": v["count"]} for k, v in cities.items()],    key=lambda x: x["ip_count"], reverse=True),
        "isps":      sorted([{"name": k, "packets": v["packets"], "ip_count": v["count"]} for k, v in isps.items()],      key=lambda x: x["ip_count"], reverse=True),
    }


_GEO_STATS_SCRIPTED_METRIC = {
    "init_script": "state.countries = [:]; state.cities = [:]; state.isps = [:]",
    "map_script": """
        if (params._source.external_ips != null) {
            for (item in params._source.external_ips) {
                def country = item.country; def city = item.city; def isp = item.isp;
                def packets = item.packet_count == null ? 0 : item.packet_count;
                if (country != null) { def k = country.toString(); if (!state.countries.containsKey(k)) { state.countries[k] = ['count': 0, 'packets': 0]; } state.countries[k].count += 1; state.countries[k].packets += packets; }
                if (city != null) { def k = city.toString(); if (!state.cities.containsKey(k)) { state.cities[k] = ['count': 0, 'packets': 0]; } state.cities[k].count += 1; state.cities[k].packets += packets; }
                if (isp != null) { def k = isp.toString(); if (!state.isps.containsKey(k)) { state.isps[k] = ['count': 0, 'packets': 0]; } state.isps[k].count += 1; state.isps[k].packets += packets; }
            }
        }
    """,
    "combine_script": "return ['countries': state.countries, 'cities': state.cities, 'isps': state.isps]",
    "reduce_script": """
        def result = ['countries': [:], 'cities': [:], 'isps': [:]];
        for (s in states) {
            for (entry in s.countries.entrySet()) { if (!result.countries.containsKey(entry.key)) { result.countries[entry.key] = ['count': 0, 'packets': 0]; } result.countries[entry.key].count += entry.value.count; result.countries[entry.key].packets += entry.value.packets; }
            for (entry in s.cities.entrySet()) { if (!result.cities.containsKey(entry.key)) { result.cities[entry.key] = ['count': 0, 'packets': 0]; } result.cities[entry.key].count += entry.value.count; result.cities[entry.key].packets += entry.value.packets; }
            for (entry in s.isps.entrySet()) { if (!result.isps.containsKey(entry.key)) { result.isps[entry.key] = ['count': 0, 'packets': 0]; } result.isps[entry.key].count += entry.value.count; result.isps[entry.key].packets += entry.value.packets; }
        }
        return result;
    """
}


def aggregate_geo_from_es(es_client, ips_index):
    """Run global geo aggregation via ES scripted_metric on pcap-ips index."""
    res = es_client.search(index=ips_index, body={
        "size": 0,
        "aggs": {"geo_stats": {"scripted_metric": _GEO_STATS_SCRIPTED_METRIC}}
    })
    aggs = res.get("aggregations", {}).get("geo_stats", {}).get("value", {})
    return {
        "countries": sorted([{"name": k, "count": v["count"], "packets": v["packets"]} for k, v in (aggs.get("countries") or {}).items()], key=lambda x: x["count"], reverse=True),
        "cities":    sorted([{"name": k, "count": v["count"], "packets": v["packets"]} for k, v in (aggs.get("cities")    or {}).items()], key=lambda x: x["count"], reverse=True),
        "isps":      sorted([{"name": k, "count": v["count"], "packets": v["packets"]} for k, v in (aggs.get("isps")      or {}).items()], key=lambda x: x["count"], reverse=True),
    }


def enrich_packet_counts(es_client, ips_index, matched_ips, hits):
    """Add packet counts to matched_ips by scanning pcap-ips for matching IPs."""
    target_ips = set(matched_ips)
    if not target_ips:
        return

    # Scroll all pcap-ips docs and sum packet_count for each matched IP
    try:
        resp = es_client.search(
            index=ips_index,
            body={"query": {"match_all": {}}, "_source": ["external_ips"], "size": 500},
            scroll="2m"
        )
        sid = resp["_scroll_id"]
        while True:
            hits_page = resp["hits"]["hits"]
            if not hits_page:
                break
            for doc in hits_page:
                for ip_entry in (doc["_source"].get("external_ips") or []):
                    ip = ip_entry.get("ip")
                    if ip in target_ips:
                        matched_ips[ip]["packet_count"] += int(ip_entry.get("packet_count") or 0)
            resp = es_client.scroll(scroll_id=sid, scroll="2m")
        try:
            es_client.clear_scroll(scroll_id=sid)
        except Exception:
            pass
    except Exception as e:
        print(f"enrich_packet_counts error: {e}")


def sort_ip_rows(rows):
    """Sort IP rows: IPs with packets first, then by descending packets, then by IP string."""
    return sorted(rows, key=lambda row: (
        0 if (row.get("packet_count") or 0) > 0 else 1,
        -(row.get("packet_count") or 0),
        str(row.get("ip") or "")
    ))


def filter_ips_by_field(external_ips, field, value):
    """Filter external_ips list to those matching field==value (case-insensitive)."""
    matched = []
    for ip_entry in external_ips:
        ip_field_value = ip_entry.get(field)
        if ip_field_value and ip_field_value.lower() == value.lower():
            matched.append({
                "ip":          ip_entry.get("ip"),
                "packet_count": ip_entry.get("packet_count", 0),
                "isp":       ip_entry.get("isp") or "Unknown",
                "city":      ip_entry.get("city") or "Unknown",
                "country":   ip_entry.get("country") or "Unknown",
                "latitude":  ip_entry.get("latitude"),
                "longitude": ip_entry.get("longitude"),
            })
    return matched


