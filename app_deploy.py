from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import io
import urllib3
import boto3
from botocore.exceptions import ClientError
from functools import wraps
from collections import Counter, defaultdict
from elastic import get_es
from dotenv import load_dotenv
import elastic
from datetime import datetime, timezone

load_dotenv()

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

    def get_site_status_context():
        return {}

from helpers import (
    scroll_all_external_ips, rebin_time_series, normalise_labels,
    get_pcap_ssl_domains, get_pcap_ip_counts, build_pcap_overview_response,
    build_global_overview_response, scroll_country_aggregation,
)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
CORS(app)
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


def sanitize_ip_records_for_insights(ip_records):
    cleaned_records = []
    for record in ip_records or []:
        if not isinstance(record, dict):
            continue
        cleaned = {k: v for k, v in record.items() if k not in ('is_internal', 'location','latitude','longitude')}
        cleaned_records.append(cleaned)
    return cleaned_records

def sanitize_ip_records_for_map(ip_records):
    cleaned_records = []
    for record in ip_records or []:
        if not isinstance(record, dict):
            continue
        rec = dict(record)
        loc = rec.get('location')
        if (rec.get('latitude') is None or rec.get('longitude') is None) and isinstance(loc, dict):
            lat = loc.get('lat')
            lon = loc.get('lon')
            if lat is not None:
                rec['latitude'] = lat
            if lon is not None:
                rec['longitude'] = lon
        rec.pop('is_internal', None)
        rec.pop('location', None)
        cleaned_records.append(rec)
    return cleaned_records


# ============= HEALTH CHECK =============
@app.route('/api/health', methods=['GET'])
def health():
    try:
        if es and es.ping():
            return jsonify({"status": "ok"})
        return jsonify({"status": "es_down"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500




# ============= IP INTELLIGENCE PROGRESS =============
@app.route('/api/ip-intelligence/progress', methods=['GET'])
def ip_intelligence_progress():
    try:
        total_unique = len(scroll_all_external_ips(es, elastic.PCAP_IPS_INDEX))
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
@app.route('/api/pcaps/<pcap_id>/timeline', methods=['GET'])
def get_time_series(pcap_id):
    try:
        data = elastic.get_time_series(pcap_id)
        target_bins = request.args.get('bins', 60, type=int)
        if data and len(data) > target_bins:
            try:
                data = rebin_time_series(data, target_bins)
            except Exception as e:
                print(f"Dynamic binning error: {e}")
        if data:
            normalise_labels(data)
        return api_response(data=data)
    except Exception as e:
        return api_response(data=[], success=False, error=str(e)), 500


# ============= STATS =============
@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        requested_pcap_id = request.args.get('pcap_id') or None
        if requested_pcap_id:
            data = elastic.get_dashboard_document(requested_pcap_id)
        else:
            data = elastic.get_latest_dashboard_document()
        if not data:
            data = {}
        data.update(get_site_status_context())
        return api_response(data=data)
    except Exception as error:
        return api_response(data=None, success=False, error=str(error)), 500


# ============= RECENT LOGS =============
@app.route('/api/recent-logs/<log_type>', methods=['GET'])
def get_recent_logs(log_type):
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        pcap_id = request.args.get('pcap_id')

        result = elastic.get_recent_logs_from_es(
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
@app.route('/api/overview', methods=['GET'])
@app.route('/api/dashboard/overview', methods=['GET'])
@app.route('/api/pcaps/<pcap_id>/summary', methods=['GET'])
def get_overview(pcap_id=None):
    try:
        scoped_pcap_id = pcap_id or request.args.get('pcap_id')
        if scoped_pcap_id:
            data = elastic.get_dashboard_document(scoped_pcap_id)
            if not data or data.get('file_id') != scoped_pcap_id:
                return api_response(data=None, success=False, error=f'No analysis found for {scoped_pcap_id}'), 404
            ssl_domains = get_pcap_ssl_domains(es, scoped_pcap_id)
            internal_ip_count, external_ip_count = get_pcap_ip_counts(es, scoped_pcap_id)
            return api_response(data=build_pcap_overview_response(data, ssl_domains, internal_ip_count, external_ip_count))
        return api_response(data=build_global_overview_response(es, elastic))
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= INSIGHTS =============
@app.route('/api/insights', methods=['GET'])
@app.route('/api/pcaps/<pcap_id>/insights', methods=['GET'])
def get_insights(pcap_id=None):
    try:
        scoped_pcap_id = pcap_id or request.args.get('pcap_id')
        if scoped_pcap_id:
            data = elastic.get_dashboard_document(scoped_pcap_id)
            if not data or data.get('file_id') != scoped_pcap_id:
                return api_response(data=None, success=False, error=f'No analysis found for {scoped_pcap_id}'), 404
            return api_response(data={
                'pcap_insights': {
                    'internal_ips':      sanitize_ip_records_for_insights(elastic.get_internal_ips_for_pcap(scoped_pcap_id)),
                    'external_ips':      sanitize_ip_records_for_insights(elastic.get_external_ips_for_pcap(scoped_pcap_id)),
                    'protocols':         data.get('protocols', []),
                    'ports':             data.get('ports', []),
                    'dns_queries':       elastic.get_dns_queries_for_pcap(scoped_pcap_id),
                    'domains':           data.get('top_dns_domains', []),
                    'urls':              data.get('top_url_domains', []),
                    'files_and_payloads': elastic.get_pcap_files(scoped_pcap_id),
                    'user_agents':       data.get('user_agents', []),
                    'ftp_session':       data.get('ftp_session') or None,
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
            infected_hosts = sorted({
                infected_host
                for hit in ih_res["hits"]["hits"]
                for infected_host in [hit["_source"].get("infected_host", "").strip()]
                if infected_host
                and infected_host.lower() not in ('unknown', 'n/a', '-', 'none', 'null', '')
                and '::' not in infected_host
                and not infected_host.startswith('231.')
                and not infected_host.startswith('224.')
                and not infected_host.startswith('239.')
            })
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
@app.route('/api/pcap/<pcap_id>', methods=['GET'])
def get_pcap_analysis(pcap_id):
    return get_overview(pcap_id=pcap_id)


@app.route('/api/pcap/latest', methods=['GET'])
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
@app.route('/api/pcaps/<pcap_id>/connections', methods=['GET'])
@app.route('/api/pcap/<pcap_id>/connections', methods=['GET'])
def get_pcap_connections(pcap_id):
    try:
        page     = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 40, type=int)
        result   = elastic.get_recent_logs_from_es(
            page=page,
            per_page=max(1, min(per_page, 100)),
            pcap_id=pcap_id,
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


@app.route('/api/pcaps/<pcap_id>/connections/export', methods=['GET'])
def export_pcap_connections(pcap_id):
    import csv
    import io
    from zeek_parser import parse_zeek_log, enrich_conn_state

    log_path = os.path.join(app.config['ZEEK_LOGS_FOLDER'], pcap_id, 'conn.log')
    if not os.path.isfile(log_path):
        return api_response(data=None, success=False, error='conn.log not found for this pcap'), 404

    logs = parse_zeek_log(log_path)

    fieldnames = ['Timestamp', 'Source IP', 'Dest IP', 'Port', 'Protocol', 'Duration', 'Service', 'Conn_state_short', 'Conn_state_long', 'Bytes']

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for row in logs:
        enrich_conn_state(row)
        orig = row.get('orig_bytes') or 0
        resp = row.get('resp_bytes') or 0
        writer.writerow({
            'Timestamp':       datetime.fromtimestamp(float(row.get('ts')), timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            'Source IP':       row.get('id.orig_h'),
            'Dest IP':         row.get('id.resp_h'),
            'Port':            row.get('id.resp_p'),
            'Protocol':        row.get('proto'),
            'Duration':        row.get('duration'),
            'Service':         row.get('service'),
            'Conn_state_short': row.get('conn_state'),
            'Conn_state_long':  row.get('conn_state_desc'),
            'Bytes':           (orig + resp) if (orig or resp) else None,
        })

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'{pcap_id}_connections.csv'
    )


# ============= FILES =============
@app.route('/api/pcap/<pcap_id>/files', methods=['GET'])
def get_pcap_files(pcap_id):
    try:
        data = elastic.get_pcap_files(pcap_id)
        return api_response(data=data)
    except Exception as e:
        return api_response(data=[], success=False, error=str(e)), 500


# ============= PCAP LIST =============
@app.route('/api/pcap/all', methods=['GET'])
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
@app.route('/api/reports/geo', methods=['GET'])
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
@app.route('/api/reports/details/<report_type>', methods=['GET'])
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


@app.route('/api/reports/details/<report_type>/<report_value>', methods=['GET'])
@app.route('/api/reports/details/<report_type>/<path:report_value>', methods=['GET'])
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


@app.route('/api/reports/<report_type>/<report_value>', methods=['GET'])
@app.route('/api/reports/<report_type>/<path:report_value>', methods=['GET'])
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


@app.route('/api/reports/<pcap_id>/<report_type>/<report_value>', methods=['GET'])
@app.route('/api/reports/<pcap_id>/<report_type>/<path:report_value>', methods=['GET'])
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
@app.route('/api/stats/global', methods=['GET'])
def get_global_stats():
    try:
        data = elastic.get_global_aggregation()
        return api_response(data=data)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= PCAP LIBRARY =============
@app.route('/api/pcaps', methods=['GET'])
@app.route('/api/pcaps/<int:sinkhole_id>', methods=['GET'])
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


@app.route('/api/pcaps/set/<int:sinkhole_id>', methods=['GET'])
def get_pcaps_set(sinkhole_id):
    """Alias for /api/pcaps — sinkhole_id is ignored, all pcaps come from ES."""
    return get_pcaps(sinkhole_id=sinkhole_id)


# ============= MAP =============
@app.route('/api/map', methods=['GET'])
def get_map_data():
    try:
        pcap_id = request.args.get('pcap_id')
        if pcap_id:
            data = sanitize_ip_records_for_map(elastic.get_external_ips_for_pcap(pcap_id))
            return api_response(data={"external_ips": data}, meta={"total_ips": len(data), "pcap_id": pcap_id})

        from aggregations import get_country_city_map
        data = get_country_city_map()
        return api_response(data=data, meta={"total_locations": len(data)})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/map/external-ips', methods=['GET'])
def get_global_map_data():
    try:
        country_data, country_packets, country_captures = scroll_country_aggregation(es, elastic.PCAP_IPS_INDEX)
        countries = [
            {"name": c, "count": n, "packets": country_packets[c], "captures": len(country_captures[c])}
            for c, n in sorted(country_data.items(), key=lambda x: x[1], reverse=True)
        ]
        return api_response(data=countries, meta={"total_countries": len(countries)})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/map/external-ips/export', methods=['GET'])
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
@app.route('/api/ip/scan/<ip_address>', methods=['GET'])
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


@app.route('/api/feedback', methods=['GET'])
def get_feedback():
    try:
        res = es.search(
            index=elastic.FEEDBACK_INDEX,
            body={
                "query": {"match_all": {}},
                "sort": [{"submitted_at": {"order": "desc"}}],
                "size": 10000,
            }
        )
        data = [hit["_source"] for hit in res["hits"]["hits"]]
        return api_response(data=data)
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


@app.route('/api/feedback/<name>', methods=['DELETE'])
def delete_feedback(name):
    try:
        es.delete(index=elastic.FEEDBACK_INDEX, id=name)
        return api_response(data={'message': f'Feedback from {name} deleted successfully'})
    except Exception as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= CEPH S3 =============
def _s3():
    return boto3.client(
        's3',
        endpoint_url=os.getenv('CEPH_RGW_ENDPOINT', 'http://localhost:7480'),
        aws_access_key_id=os.getenv('RGW_ACCESS_KEY'),
        aws_secret_access_key=os.getenv('RGW_SECRET_KEY'),
        region_name=os.getenv('RGW_REGION', 'us-east-1'),
    )

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != os.getenv('RGW_ACCESS_KEY') or auth.password != os.getenv('RGW_SECRET_KEY'):
            return api_response(data=None, success=False, error='Unauthorized'), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/ceph/buckets', methods=['GET'])
def ceph_list_buckets():
    try:
        res = _s3().list_buckets()
        buckets = [{'name': b['Name'], 'created': b['CreationDate'].isoformat()} for b in res.get('Buckets', [])]
        return api_response(data=buckets, total=len(buckets))
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e)), 500

@app.route('/api/ceph/buckets', methods=['POST'])
def ceph_create_bucket():
    body = request.get_json() or {}
    bucket = body.get('bucket')
    if not bucket:
        return api_response(data=None, success=False, error='bucket is required'), 400
    try:
        _s3().create_bucket(Bucket=bucket)
        return api_response(data={'bucket': bucket})
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e)), 500

@app.route('/api/ceph/buckets/<bucket>', methods=['DELETE'])
def ceph_delete_bucket(bucket):
    try:
        s3 = _s3()
        # Delete all objects first
        objs = s3.list_objects_v2(Bucket=bucket).get('Contents', [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={'Objects': [{'Key': o['Key']} for o in objs]})
        s3.delete_bucket(Bucket=bucket)
        return api_response(data={'bucket': bucket, 'deleted': True})
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e)), 500

@app.route('/api/ceph/buckets/<bucket>/objects', methods=['GET'])
def ceph_list_objects(bucket):
    try:
        prefix = request.args.get('prefix', '')
        res = _s3().list_objects_v2(Bucket=bucket, Prefix=prefix)
        objects = [
            {'key': o['Key'], 'size': o['Size'], 'last_modified': o['LastModified'].isoformat()}
            for o in res.get('Contents', [])
        ]
        return api_response(data=objects, total=len(objects))
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e)), 500

@app.route('/api/ceph/buckets/<bucket>/objects/<path:key>', methods=['PUT'])
def ceph_upload_object(bucket, key):
    if 'file' not in request.files:
        return api_response(data=None, success=False, error='file is required'), 400
    try:
        f = request.files['file']
        _s3().upload_fileobj(f, bucket, key)
        return api_response(data={'bucket': bucket, 'key': key})
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e)), 500

@app.route('/api/ceph/buckets/<bucket>/objects/<path:key>', methods=['GET'])
def ceph_download_object(bucket, key):
    try:
        res = _s3().get_object(Bucket=bucket, Key=key)
        return send_file(
            io.BytesIO(res['Body'].read()),
            download_name=key.split('/')[-1],
            as_attachment=True
        )
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e)), 500

@app.route('/api/ceph/buckets/<bucket>/objects/<path:key>', methods=['DELETE'])
def ceph_delete_object(bucket, key):
    try:
        _s3().delete_object(Bucket=bucket, Key=key)
        return api_response(data={'bucket': bucket, 'key': key, 'deleted': True})
    except ClientError as e:
        return api_response(data=None, success=False, error=str(e)), 500


# ============= MAIN =============
if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False, port=8000)