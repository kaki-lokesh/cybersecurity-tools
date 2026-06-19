"""
reporter.py
Generates analyst-ready text and JSON reports from aggregated intelligence data.
Supports IP addresses, domains, and file hashes.
"""
import json
from datetime import datetime

def generate_ip_report(ip, results, risk):
    """Generate a formatted analyst report for an IP address investigation"""
    lines = []
    sep = '=' * 62
    lines.append(sep)
    lines.append(f'  THREAT INTELLIGENCE REPORT - {ip}')
    lines.append(f'  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}')
    lines.append(f'  Query time: {results.get("_meta", {}).get("query_time_s", "?")}s')
    lines.append(sep)

    # Risk banner : most prominent element
    lines.append(f'\n{risk["colour"]} RISK LEVEL: {risk["level"]} ({risk["score"]}/100)\n')
    if risk['evidence']:
        lines.append('  Scoring evidence:')
        for e in risk['evidence']:
            lines.append(f'    . {e}')
    lines.append('')

    # Geolocation and network identity
    shodan = results.get('shodan', {})
    lines.append('[IDENTITY]')
    lines.append(f'  Organisation : {shodan.get("organisation", "Unknown")}')
    lines.append(f'  ASN          : {shodan.get("asn", "Unknown")}')
    lines.append(f'  Country      : {shodan.get("country", "Unknown")}')
    lines.append(f'  City         : {shodan.get("city", "Unknown")}')
    lines.append(f'  Hostnames    : {", ".join(shodan.get("hostnames", [])) or "None found"}')
    lines.append('')

    # Exposure : open ports and services from Shodan
    open_ports = shodan.get('open_ports', [])
    lines.append(f'[EXPOSURE - {len(open_ports)} PORT(S) OPEN]')
    for svc in shodan.get('services', [])[:8]:  # Top 8 services
        port_str = f'{svc["port"]}/{svc["transport"]}'
        svc_str  = f'{svc.get("product","")} {svc.get("version","")}'.strip() or 'Unknown'
        vuln_str = f'   CVEs: {", ".join(svc.get("vulnerabilities",[]))}' if svc.get('vulnerabilities') else ''
        lines.append(f'  {port_str:<10} {svc_str}{vuln_str}')
    lines.append('')

    # VirusTotal summary
    vt = results.get('virustotal', {})
    vt_stats = vt.get('detection_stats', {})
    lines.append('[VIRUSTOTAL]')
    lines.append(f'  Detections  : {vt_stats.get("detection_rate", "N/A")}')
    lines.append(f'  Reputation  : {vt.get("reputation", "N/A")}')
    lines.append(f'  Tags        : {", ".join(vt.get("tags", [])) or "None"}')
    lines.append('')

    # AbuseIPDB summary
    ab = results.get('abuseipdb', {})
    lines.append('[ABUSEIPDB]')
    lines.append(f'  Confidence  : {ab.get("abuse_confidence", "N/A")}%')
    lines.append(f'  Reports     : {ab.get("total_reports", "N/A")} from {ab.get("num_distinct_users", "?")} users')
    lines.append(f'  Last seen   : {ab.get("last_reported", "Never")}')
    lines.append(f'  Usage type  : {ab.get("usage_type", "Unknown")}')
    lines.append('')

    # Vulnerabilities section
    all_vulns = shodan.get('vulnerabilities', [])
    if all_vulns:
        lines.append(f'[KNOWN VULNERABILITIES ({len(all_vulns)} CVEs found by Shodan)]')
        for cve in all_vulns[:10]:
            lines.append(f'   {cve} - search NVD for details')
        lines.append('')

    # Analyst recommendation
    lines.append('[ANALYST RECOMMENDATION]')
    rec_map = {
        'CRITICAL': 'BLOCK immediately. Do not allow outbound connections. Escalate to incident response.',
        'HIGH':     'INVESTIGATE further. Consider blocking. Review logs for connections to this IP.',
        'MEDIUM':   'MONITOR. Increase logging for traffic involving this IP.',
        'LOW':      'ALLOW with standard monitoring. No immediate action required.'
    }
    lines.append(f'  {rec_map.get(risk["level"], "No recommendation available.")}')
    lines.append('')
    lines.append(sep)
    return '\n'.join(lines)


def generate_hash_report(file_hash, vt_result):
    """Generate a report for file hash analysis"""
    lines = []
    sep = '=' * 62
    lines.append(sep)
    lines.append(f'  FILE HASH ANALYSIS REPORT - {file_hash[:32]}...')
    lines.append(f'  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}')
    lines.append(sep)
    if 'error' in vt_result:
        lines.append(f'\n  Error: {vt_result["error"]}\n')
        return '\n'.join(lines)
    stats = vt_result.get('detection_stats', {})
    mal   = stats.get('malicious', 0)
    total = stats.get('total_engines', 0)
    verdict = '🔴 MALICIOUS' if mal > 3 else ('🟡 SUSPICIOUS' if mal > 0 else '🟢 CLEAN')
    lines.append(f'\n  Verdict      : {verdict}')
    lines.append(f'  Detection    : {stats.get("detection_rate", "N/A")}')
    lines.append(f'  File name    : {vt_result.get("name", "Unknown")}')
    lines.append(f'  File type    : {vt_result.get("file_type", "Unknown")}')
    lines.append(f'  Malware family: {vt_result.get("malware_family", "None identified")}')
    lines.append(f'  First seen   : {vt_result.get("first_seen", "Unknown")}')
    lines.append(f'  Tags         : {", ".join(vt_result.get("tags", [])) or "None"}')
    lines.append(f'\n{sep}')
    return '\n'.join(lines)