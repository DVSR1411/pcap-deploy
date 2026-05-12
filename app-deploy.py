from flask import Flask, request, jsonify
import os
import urllib3

from elastic import get_es
import elastic

try:
    from zeek_parser import (
        get_internal_tcp_udp_ip_aggregation_from_conn_log,
        get_internal_tcp_udp_ip_aggregation_from_conn_logs,
        get_site_status_context,
    )
except ImportError:
    def get_internal_tcp_udp_ip_aggregation_from_conn_log(_):
        return {"ips": [], "count": 0}

    def get_internal_tcp_udp_ip_aggregation_from_conn_logs(_):
        return {"ips": [], "count": 0}

    def get_site_status_context(es, zeek_logs_folder=None):
        return {}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['ZEEK_LOGS_FOLDER'] = os.path.join(basedir, 'zeek_logs')

# Ensure index exists
es = get_es()
ES_HOST = os.getenv('ES_HOST', 'http://localhost:9200')

try:
    elastic.create_granular_indexes()
    elastic.create_feedback_index()
except Exception as e:
    print(f'Warning: Could not create Elasticsearch index: {e}')


# ============= API RESPONSE HELPER =============
def get_conn_state_description(state):
    """Return human-readable description for Zeek connection state"""
    states = {
        'S0': 'SYN sent, no reply',
        'S1': 'Connected, not closed',
        'SF': 'Normal connect & close',
        'REJ': 'Connection rejected',
        'S2': 'Initiator close, no reply',
        'S3': 'Responder close, no reply',
        'RSTO': 'Initiator reset',
        'RSTR': 'Responder reset',
        'RSTOS0': 'SYN then reset',
        'RSTRH': 'SYN-ACK then reset',
        'SH': 'SYN then FIN',
        'SHR': 'SYN-ACK then FIN',
        'OTH': 'No SYN, midstream traffic'
    }
    return states.get(str(state).upper(), state)

def api_response(data, success=True, page=None, per_page=None, total=None, total_pages=None, error=None, meta=None):
    response = {
        'success': success,
        'data': data
    }
    if error:
        response['error'] = error

    if page is not None or per_page is not None or total is not None:
        response['pagination'] = {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': total_pages
        }

    if meta:
        response.update(meta)

    return jsonify(response)


# ============= HEALTH CHECK =============
@app.route('/api/health')
def health():
    try:
        if es and es.ping():
            return jsonify({"status": "ok"})
        return jsonify({"status": "es_down"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ============= IP INTELLIGENCE PROGRESS =============
@app.route('/api/ip-intelligence/progress')
def ip_intelligence_progress():
    try:
        all_ips = set()
        resp = es.search(index=elastic.PCAP_IPS_INDEX, body={
            "query": {"match_all": {}},
            "_source": ["external_ips.ip"], "size": 500
        }, scroll="2m")
        sid = resp["_scroll_id"]
        while True:
            hits = resp["hits"]["hits"]
            if not hits:
                break
            for h in hits:
                for entry in (h["_source"].get("external_ips") or []):
                    ip = entry.get("ip")
                    if ip:
                        all_ips.add(ip)
            resp = es.scroll(scroll_id=sid, scroll="2m")
        try:
            es.clear_scroll(scroll_id=sid)
        except Exception:
            pass
        total_unique = len(all_ips)
        done = es.count(index=elastic.IP_INTEL_INDEX, body={"query": {"match_all": {}}})['count']
        remaining = max(total_unique - done, 0)
        pct = round(done / total_unique * 100, 2) if total_unique else 0
        return api_response(data={
            'total_unique_ips': total_unique,
            'completed': done,
            'remaining': remaining,
            'progress_pct': pct,
        })
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= TIMELINE / TIME SERIES =============
@app.route('/api/pcaps/<pcap_id>/timeline')
def get_time_series(pcap_id):
    try:
        data = elastic.get_time_series(pcap_id)
        
        target_bins = request.args.get('bins', 60, type=int)
        
        if data and len(data) > target_bins:
            from datetime import datetime, timezone
            from collections import defaultdict
            try:
                start_ts = datetime.fromisoformat(data[0]['label']).timestamp()
                end_ts = datetime.fromisoformat(data[-1]['label']).timestamp()
                duration = end_ts - start_ts
                interval_seconds = max(30, int(duration / target_bins))

                re_binned = defaultdict(int)
                for point in data:
                    epoch = datetime.fromisoformat(point['label']).timestamp()
                    bucket_epoch = int(epoch - (epoch % interval_seconds))
                    re_binned[bucket_epoch] += point['value']

                result = []
                for bucket_epoch in sorted(re_binned.keys()):
                    label = datetime.fromtimestamp(bucket_epoch, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                    result.append({"label": label, "value": re_binned[bucket_epoch]})
                data = result
            except Exception as e:
                print(f"Dynamic binning error: {e}")
        
        if data:
            from datetime import datetime
            for point in data:
                try:
                    if 'T' in str(point['label']):
                        dt = datetime.fromisoformat(point['label'])
                        point['label'] = dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass

        return api_response(data=data)
    except Exception as e:
        return api_response(data=[], success=False, error=str(e)), 500


# ============= STATS =============
@app.route('/api/stats')
def get_stats():
    try:
        requested_pcap_id = request.args.get('pcap_id') or None
        if requested_pcap_id:
            data = elastic.get_dashboard_document(requested_pcap_id)
        else:
            data = elastic.get_latest_dashboard_document()
        if not data:
            data = {}
        data.update(get_site_status_context(es, app.config.get('ZEEK_LOGS_FOLDER')))
        return api_response(data=data)
    except Exception as error:
        return api_response(data=None, success=False, error=str(error)), 500


# ============= RECENT LOGS =============
@app.route('/api/recent-logs/<log_type>')
def get_recent_logs(log_type):
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        pcap_id = request.args.get('pcap_id')

        result = elastic.get_recent_logs_from_es(
            log_type=log_type,
            page=page,
            per_page=per_page,
            pcap_id=pcap_id
        )
        return api_response(
            data=result.get('logs', []),
            page=result.get('page'),
            per_page=result.get('per_page'),
            total=result.get('total'),
            total_pages=result.get('total_pages')
        )
    except Exception as e:
        return api_response(data=[], success=False, error=str(e)), 500


# ============= PCAP OVERVIEW =============
@app.route('/api/overview')
@app.route('/api/dashboard/overview')
@app.route('/api/pcaps/<pcap_id>/summary')
def get_overview(pcap_id=None):
    try:
        scoped_pcap_id = pcap_id or request.args.get('pcap_id')
        if scoped_pcap_id:
            data = elastic.get_dashboard_document(scoped_pcap_id)
            if not data or data.get('file_id') != scoped_pcap_id:
                return api_response(data=None, success=False, error=f'No analysis found for {scoped_pcap_id}'), 404
            
            from collections import Counter
            ssl_domains = []
            try:
                dns_res = es.search(
                    index='pcap-dns',
                    body={
                        "query": {"term": {"pcap_id": scoped_pcap_id}},
                        "_source": ["domains"],
                        "size": 1
                    }
                )
                if dns_res["hits"]["hits"]:
                    domains = dns_res["hits"]["hits"][0]["_source"].get("domains", [])
                    ssl_counter = Counter()
                    for d in domains:
                        if d.get("type") == "ssl":
                            ssl_counter[d.get("domain")] += d.get("count", 0)
                    ssl_domains = [{'label': k, 'value': v} for k, v in ssl_counter.most_common(10)]
            except Exception as e:
                print(f"Error fetching SSL domains for {scoped_pcap_id}: {e}")
            
            internal_ip_count = 0
            external_ip_count = 0
            try:
                ips_res = es.get(index=elastic.PCAP_IPS_INDEX, id=scoped_pcap_id)
                ips_data = ips_res["_source"]
                internal_ip_count = len(ips_data.get("internal_ips", []))
                external_ip_count = len(ips_data.get("external_ips", []))
            except Exception:
                pass
            
            return api_response(data={
                'capture_summary': {
                    'file_name': data.get('pcap_filename') or data.get('file_name'),
                    'pcap_packets': data.get('total_packets') or data.get('exact_pcap_packets'),
                    'connections': data.get('total_connections'),
                    'bytes': data.get('total_bytes'),
                    'file_size': data.get('file_size'),
                    'duration_seconds': data.get('duration_seconds'),
                    'start_time_utc': data.get('start_time_utc'),
                    'end_time_utc': data.get('end_time_utc'),
                    'infected_host': data.get('infected_host') or 'Unknown',
                    'internal_ip_count': internal_ip_count,
                    'external_ip_count': external_ip_count,
                },
                'traffic_distribution': {
                    'transport': data.get('transport_breakdown', []),
                    'application': data.get('application_breakdown', []),
                    'direction': data.get('direction_breakdown', []),
                    'dns_domains': [{'domain': d.get('label'), 'count': d.get('value', 0)} for d in (data.get('top_dns_domains') or [])[:10]],
                    'url_domains': [{'domain': d.get('label'), 'count': d.get('value', 0)} for d in (data.get('top_url_domains') or [])[:10]],
                    'top_ssl_domains': ssl_domains,
                }
            })
        
        from collections import Counter, defaultdict

        all_docs = []
        res = es.search(
            index=elastic.PCAP_METADATA_INDEX,
            body={
                "query": {"match_all": {}},
                "_source": [
                    "total_packets", "total_connections", "total_bytes",
                    "file_size", "duration_seconds", "infected_host",
                    "transport_breakdown", "application_breakdown", "direction_breakdown",
                    "top_dns_domains", "top_url_domains"
                ],
                "size": 10000
            },
            scroll="2m"
        )
        scroll_id = res["_scroll_id"]
        hits = res["hits"]["hits"]
        all_docs.extend(hits)
        while len(hits) > 0:
            res = es.scroll(scroll_id=scroll_id, scroll="2m")
            hits = res["hits"]["hits"]
            all_docs.extend(hits)
        try:
            es.clear_scroll(scroll_id=scroll_id)
        except Exception:
            pass

        total_packets = 0
        total_connections = 0
        total_bytes = 0
        total_file_size = 0
        total_duration = 0.0
        infected_hosts = set()
        transport_totals = Counter()
        application_totals = Counter()
        direction_totals = Counter()
        dns_domain_totals = Counter()
        url_domain_totals = Counter()
        ssl_domain_totals = Counter()
        pcap_count = len(all_docs)

        for hit in all_docs:
            src = hit["_source"]
            if src.get('total_packets') is not None:
                total_packets += int(src['total_packets'])
            if src.get('total_connections') is not None:
                total_connections += int(src['total_connections'])
            if src.get('total_bytes') is not None:
                total_bytes += int(src['total_bytes'])
            if src.get('file_size') is not None:
                total_file_size += int(src['file_size'])
            if src.get('duration_seconds') is not None:
                total_duration += float(src['duration_seconds'])
            infected = src.get('infected_host')
            if infected:
                infected_str = str(infected).strip()
                if (infected_str and
                    infected_str not in ('Unknown', 'N/A', '-', 'None', 'null') and
                    '::' not in infected_str and
                    not infected_str.startswith('231.') and
                    not infected_str.startswith('224.') and
                    not infected_str.startswith('239.')):
                    infected_hosts.add(infected_str)
            for item in (src.get('transport_breakdown') or []):
                if item.get('label') and item.get('value') is not None:
                    transport_totals[item['label']] += int(item['value'])
            for item in (src.get('application_breakdown') or []):
                if item.get('label') and item.get('value') is not None:
                    application_totals[item['label']] += int(item['value'])
            for item in (src.get('direction_breakdown') or []):
                if item.get('label') and item.get('value') is not None:
                    direction_totals[item['label']] += int(item['value'])
            for item in (src.get('top_dns_domains') or []):
                if item.get('label') and item.get('value') is not None:
                    dns_domain_totals[item['label']] += int(item['value'])
            for item in (src.get('top_url_domains') or []):
                if item.get('label') and item.get('value') is not None:
                    url_domain_totals[item['label']] += int(item['value'])

        try:
            dns_res = es.search(
                index='pcap-dns',
                body={"query": {"match_all": {}}, "_source": ["domains"], "size": 10000},
                scroll="2m"
            )
            dns_scroll_id = dns_res["_scroll_id"]
            dns_hits = dns_res["hits"]["hits"]
            while len(dns_hits) > 0:
                for hit in dns_hits:
                    for d in hit["_source"].get("domains", []):
                        if d.get("type") == "ssl" and d.get("domain") and d.get("count") is not None:
                            ssl_domain_totals[d["domain"]] += int(d["count"])
                dns_res = es.scroll(scroll_id=dns_scroll_id, scroll="2m")
                dns_hits = dns_res["hits"]["hits"]
            try:
                es.clear_scroll(scroll_id=dns_scroll_id)
            except Exception:
                pass
        except Exception:
            pass

        unique_internal_ips = set()
        unique_external_ips = set()
        try:
            ips_res = es.search(
                index=elastic.PCAP_IPS_INDEX,
                body={"query": {"match_all": {}}, "_source": ["internal_ips.ip", "external_ips.ip"], "size": 10000},
                scroll="2m"
            )
            ips_scroll_id = ips_res["_scroll_id"]
            ips_hits = ips_res["hits"]["hits"]
            while len(ips_hits) > 0:
                for hit in ips_hits:
                    for ip in (hit["_source"].get("internal_ips", [])):
                        if ip.get("ip"):
                            unique_internal_ips.add(ip["ip"])
                    for ip in (hit["_source"].get("external_ips", [])):
                        if ip.get("ip"):
                            unique_external_ips.add(ip["ip"])
                ips_res = es.scroll(scroll_id=ips_scroll_id, scroll="2m")
                ips_hits = ips_res["hits"]["hits"]
            try:
                es.clear_scroll(scroll_id=ips_scroll_id)
            except Exception:
                pass
        except Exception:
            pass

        return api_response(data={
            'capture_summary': {
                'total_pcaps': pcap_count,
                'pcap_packets': total_packets,
                'connections': total_connections,
                'bytes': total_bytes,
                'file_size': total_file_size,
                'duration_seconds': round(total_duration, 2),
                'infected_hosts': sorted(list(infected_hosts)),
                'infected_hosts_count': len(infected_hosts),
                'internal_ip_count': len(unique_internal_ips),
                'external_ip_count': len(unique_external_ips),
            },
            'traffic_distribution': {
                'transport': [{'label': k, 'value': v} for k, v in sorted(transport_totals.items(), key=lambda x: x[1], reverse=True)],
                'application': [{'label': k, 'value': v} for k, v in sorted(application_totals.items(), key=lambda x: x[1], reverse=True)],
                'direction': [{'label': k, 'value': v} for k, v in sorted(direction_totals.items(), key=lambda x: x[1], reverse=True)],
                'dns_domains': [{'domain': k, 'count': v} for k, v in sorted(dns_domain_totals.items(), key=lambda x: x[1], reverse=True)[:10]],
                'url_domains': [{'domain': k, 'count': v} for k, v in sorted(url_domain_totals.items(), key=lambda x: x[1], reverse=True)[:10]],
                'top_ssl_domains': [{'label': k, 'value': v} for k, v in sorted(ssl_domain_totals.items(), key=lambda x: x[1], reverse=True)[:10]],
            }
        })
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= INSIGHTS =============
@app.route('/api/insights')
@app.route('/api/pcaps/<pcap_id>/insights')
def get_insights(pcap_id=None):
    try:
        scoped_pcap_id = pcap_id or request.args.get('pcap_id')
        if scoped_pcap_id:
            data = elastic.get_dashboard_document(scoped_pcap_id)
            if not data or data.get('file_id') != scoped_pcap_id:
                return api_response(data=None, success=False, error=f'No analysis found for {scoped_pcap_id}'), 404
            return api_response(data={
                'pcap_insights': {
                    'internal_ips':      elastic.get_internal_ips_for_pcap(scoped_pcap_id),
                    'external_ips':      elastic.get_external_ips_for_pcap(scoped_pcap_id),
                    'protocols':         data.get('protocols', []),
                    'ports':             data.get('ports', []),
                    'dns_queries':       elastic.get_dns_queries_for_pcap(scoped_pcap_id),
                    'domains':           data.get('top_dns_domains', []),
                    'urls':              data.get('top_url_domains', []),
                    'files_and_payloads': elastic.get_pcap_files(scoped_pcap_id),
                    'user_agents':       data.get('user_agents', []),
                }
            })
        global_stats = elastic.get_global_aggregation()
        ip_breakdown = elastic.get_ip_breakdown()
        infected_hosts = []
        try:
            ih_res = es.search(
                index=elastic.PCAP_METADATA_INDEX,
                body={
                    "query": {"bool": {"must_not": [{"terms": {"infected_host.keyword": ["Unknown", "N/A", "-", "None", "null", ""]}}]}},
                    "_source": ["infected_host"],
                    "size": 10000
                }
            )
            infected_hosts = sorted(set(
                h for h in (
                    hit["_source"]["infected_host"].strip()
                    for hit in ih_res["hits"]["hits"]
                    if hit["_source"].get("infected_host", "").strip()
                )
                if h
                and h.lower() not in ('unknown', 'n/a', '-', 'none', 'null', '')
                and '::' not in h
                and not h.startswith('231.')
                and not h.startswith('224.')
                and not h.startswith('239.')
            ))
        except Exception:
            pass
        return api_response(data={
            'insights_trends': {
                'infected_hosts':     infected_hosts,
                'infected_hosts_count': len(infected_hosts),
                'top_active_ips':    (global_stats.get('top_active_ips') or [])[:10],
                'top_countries':      (ip_breakdown.get('countries') or [])[:10],
                'top_isps':           (ip_breakdown.get('isps') or [])[:10],
                'top_cities':         (ip_breakdown.get('cities') or [])[:10],
            }
        })
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= LEGACY ROUTES =============
@app.route('/api/pcap/<pcap_id>')
def get_pcap_analysis(pcap_id):
    return get_overview(pcap_id=pcap_id)


@app.route('/api/pcap/latest')
def get_latest_pcap_analysis():
    try:
        data = elastic.get_latest_dashboard_document()
        if data:
            data.pop('recent_connections', None)
            data.pop('file_payloads', None)
            return api_response(data=data)
        return api_response(data=None, success=False, error='No dashboard documents found in Elasticsearch'), 404
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= CONNECTIONS =============
@app.route('/api/pcaps/<pcap_id>/connections')
@app.route('/api/pcap/<pcap_id>/connections')
def get_pcap_connections(pcap_id):
    try:
        page     = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 40, type=int)
        timeline = request.args.get('timeline')
        result   = elastic.get_recent_logs_from_es(
            log_type='conn', page=page,
            per_page=max(1, min(per_page, 100)),
            pcap_id=pcap_id, timeline=timeline,
            zeek_logs_folder=app.config['ZEEK_LOGS_FOLDER']
        )
        return api_response(
            data=result.get('logs', []),
            page=result.get('page'),
            per_page=result.get('per_page'),
            total=result.get('total'),
            total_pages=result.get('total_pages')
        )
    except Exception as e:
        return api_response(data=[], success=False, error=str(e)), 500


# ============= FILES =============
@app.route('/api/pcap/<pcap_id>/files')
def get_pcap_files(pcap_id):
    try:
        data = elastic.get_pcap_files(pcap_id)
        return api_response(data=data)
    except Exception as e:
        return api_response(data=[], success=False, error=str(e)), 500


# ============= PCAP LIST =============
@app.route('/api/pcap/all')
def get_all_pcap_analyses():
    try:
        res = es.search(
            index=elastic.PCAP_METADATA_INDEX,
            body={
                "query": {"match_all": {}},
                "_source": ["pcap_id", "pcap_filename", "file_name", "file_size", "total_packets", "duration_seconds", "unique_ips", "analysis_timestamp"],
                "size": 10000,
                "sort": [{"analysis_timestamp": {"order": "desc"}}]
            }
        )
        data = [hit["_source"] for hit in res["hits"]["hits"]]
        return api_response(data=data, total=len(data))
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= GEO REPORT =============
@app.route('/api/reports/geo')
def get_geo_report():
    try:
        pcap_id = request.args.get('pcap_id')
        data = elastic.get_geo_aggregation(pcap_id)
        data = {
            "countries": [{"name": c["name"]} for c in data.get("countries", [])],
            "isps":      [{"name": c["name"]} for c in data.get("isps", [])],
        }
        return api_response(data=data)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= REPORT DETAILS =============
@app.route('/api/reports/details/<report_type>')
def get_report_type_list(report_type):
    try:
        data = elastic.get_geo_aggregation()
        key_map = {'country': 'countries', 'isp': 'isps', 'city': 'cities'}
        key = key_map.get(report_type.lower())
        if not key:
            return api_response(data=None, success=False, error=f'Unknown report type: {report_type}'), 400
        return api_response(data=data.get(key, []), meta={"report_type": report_type})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/reports/details/<report_type>/<report_value>')
@app.route('/api/reports/details/<report_type>/<path:report_value>')
def get_report_details_path(report_type, report_value):
    try:
        data = elastic.get_report_details(report_type, report_value)
        return api_response(data=data, meta={
            "total_unique_ips": len(data),
            "report_type": report_type,
            "filter_value": report_value
        })
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/reports/<report_type>/<report_value>')
@app.route('/api/reports/<report_type>/<path:report_value>')
def get_global_report_details(report_type, report_value):
    try:
        data = elastic.get_report_details(report_type, report_value)
        return api_response(data=data, meta={
            "total_unique_ips": len(data),
            "report_type": report_type,
            "filter_value": report_value
        })
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/reports/<pcap_id>/<report_type>/<report_value>')
@app.route('/api/reports/<pcap_id>/<report_type>/<path:report_value>')
def get_pcap_report_details(pcap_id, report_type, report_value):
    try:
        data = elastic.get_pcap_report_details(pcap_id, report_type, report_value)
        return api_response(data=data, meta={
            "total_unique_ips": len(data),
            "report_type": report_type,
            "filter_value": report_value,
            "pcap_id": pcap_id
        })
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= GLOBAL STATS =============
@app.route('/api/stats/global')
def get_global_stats():
    try:
        data = elastic.get_global_aggregation()
        return api_response(data=data)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= PCAP LIBRARY =============
@app.route('/api/pcaps')
@app.route('/api/pcaps/<int:sinkhole_id>')
def get_pcaps(sinkhole_id=1):
    try:
        search = request.args.get('search', '', type=str).lower()
        
        query = {"match_all": {}}
        if search:
            query = {"wildcard": {"pcap_filename": {"value": f"*{search}*", "case_insensitive": True}}}
        
        res = es.search(
            index=elastic.PCAP_METADATA_INDEX,
            body={
                "query": query,
                "_source": ["pcap_id", "pcap_filename", "file_name", "file_size", "total_packets", "duration_seconds"],
                "size": 10000,
                "sort": [{"analysis_timestamp": {"order": "desc"}}]
            }
        )
        
        hits = res["hits"]["hits"]
        pcap_ids = [h["_source"].get("pcap_id") for h in hits if h["_source"].get("pcap_id")]

        ip_count_map = {}
        if pcap_ids:
            mget_res = es.mget(
                index=elastic.PCAP_IPS_INDEX,
                body={"ids": pcap_ids},
                _source=["external_ips"]
            )
            for doc in mget_res["docs"]:
                if doc.get("found"):
                    ip_count_map[doc["_id"]] = len(doc["_source"].get("external_ips") or [])

        all_pcaps = []
        for hit in hits:
            src = hit["_source"]
            pcap_id = src.get("pcap_id")
            filename = src.get("pcap_filename") or src.get("file_name") or ""

            all_pcaps.append({
                "pcap_id": pcap_id,
                "filename": filename,
                "size": src.get("file_size") or 0,
                "packets": src.get("total_packets") or 0,
                "duration": src.get("duration_seconds") or 0,
                "ip_count": ip_count_map.get(pcap_id, 0)
            })
        
        total = res["hits"]["total"]["value"] if isinstance(res["hits"]["total"], dict) else res["hits"]["total"]
        
        return api_response(
            data=all_pcaps,
            total=total,
            meta={"repository_stats": elastic.get_repository_stats()}
        )
    except Exception as e:
        print(f"Error in /api/pcaps: {e}")
        return api_response(data=[], success=False, error=str(e)), 500


@app.route('/api/pcaps/set/<int:sinkhole_id>')
def get_pcaps_set(sinkhole_id):
    """Alias for /api/pcaps — sinkhole_id is ignored, all pcaps come from ES."""
    return get_pcaps(sinkhole_id=sinkhole_id)


# ============= MAP =============
@app.route('/api/map')
def get_map_data():
    try:
        from aggregations import get_country_city_map
        pcap_id = request.args.get('pcap_id')
        data = get_country_city_map(pcap_id)
        return api_response(data=data, meta={"total_locations": len(data)})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/map/external-ips')
def get_global_map_data():
    try:
        from collections import Counter, defaultdict
        country_data = Counter()
        country_packets = Counter()
        country_captures = defaultdict(set)

        resp = es.search(
            index=elastic.PCAP_IPS_INDEX,
            body={"query": {"match_all": {}}, "_source": ["external_ips", "pcap_id"], "size": 10000},
            scroll="2m"
        )
        scroll_id = resp["_scroll_id"]
        hits = resp["hits"]["hits"]
        while len(hits) > 0:
            for hit in hits:
                pcap_id = hit["_source"].get("pcap_id")
                for ip_entry in hit["_source"].get("external_ips", []):
                    country = ip_entry.get("country")
                    if country:
                        country_data[country] += 1
                        country_packets[country] += ip_entry.get("packet_count", 0)
                        if pcap_id:
                            country_captures[country].add(pcap_id)
            resp = es.scroll(scroll_id=scroll_id, scroll="2m")
            hits = resp["hits"]["hits"]
        try:
            es.clear_scroll(scroll_id=scroll_id)
        except Exception:
            pass

        countries = [
            {"name": country, "count": count, "packets": country_packets[country], "captures": len(country_captures[country])}
            for country, count in sorted(country_data.items(), key=lambda x: x[1], reverse=True)
        ]
        return api_response(data=countries, meta={"total_countries": len(countries)})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/map/external-ips/export')
def export_external_ips():
    try:
        from aggregations import get_all_external_ips
        rows = get_all_external_ips(limit=10000)  # kept at 10000 per requirement
        response = api_response(data=rows, meta={"total_ips": len(rows)})
        response.headers['Content-Disposition'] = 'attachment; filename=external_ips.json'
        return response
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= IP SCAN =============
@app.route('/api/ip/scan/<ip_address>')
def scan_ip_details(ip_address):
    try:
        data = elastic.get_ip_scan(ip_address)
        if data:
            if 'ports' in data and isinstance(data['ports'], list):
                data['ports'] = [
                    {k: v for k, v in port.items() if k not in ('http', 'tls', 'scripts')}
                    for port in data['ports']
                ]
            return api_response(data=data)

        geo = elastic.get_ip_geo_from_pcap_ips(ip_address)
        partial = {
            'ip': ip_address,
            'status': 'pending',
            'geo': geo,
            'asn': geo.get('asn'),
            'rdns': 'N/A',
            'hostnames': [],
            'whois': {},
            'os_info': {},
            'dnsbl': {'listed': None, 'total_listings': 0, 'providers': []},
            'ports': [],
        }
        return api_response(data=partial, success=True)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= FEEDBACK =============
@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    name         = (request.form.get('name') or '').strip()
    email        = (request.form.get('email') or '').strip()
    organisation = (request.form.get('organisation') or '').strip()
    message      = (request.form.get('message') or '').strip()

    if not name or not email or not message:
        return api_response(data=None, success=False, error='name, email and message are required'), 400

    try:
        elastic.index_feedback(name, email, organisation, message)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500

    return api_response(data={'message': 'Feedback submitted successfully'})


# ============= MAIN =============
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False, port=5000)
