import requests, os

VT_BASE = 'https://www.virustotal.com/api/v3'

def _vt_headers():
    key = os.environ.get('VIRUSTOTAL_API_KEY')
    if not key:
        return None
    return {'x-apikey': key, 'Accept': 'application/json'}

def _parse_stats(attributes):
    """Extract detection stats from VT analysis results"""
    stats = attributes.get('last_analysis_stats', {})
    total = sum(stats.values())
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    return {
        'malicious':   malicious,
        'suspicious':  suspicious,
        'harmless':    stats.get('harmless', 0),
        'undetected':  stats.get('undetected', 0),
        'total_engines': total,
        'detection_rate': f'{malicious}/{total}' if total else '0/0'
    }

def query_vt_ip(ip):
    """Query VirusTotal for IP address reputation and related intelligence."""
    hdrs = _vt_headers()
    if not hdrs:
        return {'source': 'VirusTotal', 'error': 'VIRUSTOTAL_API_KEY not set'}
    try:
        r = requests.get(f'{VT_BASE}/ip_addresses/{ip}', headers=hdrs, timeout=12)
        if r.status_code != 200:
            return {'source': 'VirusTotal', 'error': f'HTTP {r.status_code}'}
        attr = r.json()['data']['attributes']
        return {
            'source':          'VirusTotal',
            'reputation':      attr.get('reputation', 0),
            'detection_stats': _parse_stats(attr),
            'network':         attr.get('network'),
            'country':         attr.get('country'),
            'as_owner':        attr.get('as_owner'),
            'asn':             attr.get('asn'),
            'tags':            attr.get('tags', []),
            'total_votes':     attr.get('total_votes', {}),
        }
    except Exception as e:
        return {'source': 'VirusTotal', 'error': str(e)}

def query_vt_hash(file_hash):
    """Query VirusTotal for file hash analysis results"""
    hdrs = _vt_headers()
    if not hdrs: return {'source': 'VirusTotal', 'error': 'No API key'}
    try:
        r = requests.get(f'{VT_BASE}/files/{file_hash}', headers=hdrs, timeout=12)
        if r.status_code == 404:
            return {'source': 'VirusTotal', 'error': 'Hash not found in VT database'}
        attr = r.json()['data']['attributes']
        return {
            'source':          'VirusTotal',
            'sha256':          attr.get('sha256'),
            'sha1':            attr.get('sha1'),
            'md5':             attr.get('md5'),
            'file_type':       attr.get('type_description'),
            'file_size':       attr.get('size'),
            'name':            attr.get('meaningful_name', 'Unknown'),
            'malware_family':  attr.get('popular_threat_classification', {}).get('suggested_threat_label'),
            'detection_stats': _parse_stats(attr),
            'first_seen':      attr.get('first_submission_date'),
            'last_analysis':   attr.get('last_analysis_date'),
            'tags':            attr.get('tags', []),
        }
    except Exception as e:
        return {'source': 'VirusTotal', 'error': str(e)}