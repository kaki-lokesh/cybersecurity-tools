"""
aggregator.py
Runs all API queries in parallel and aggregates results.
Calculates a composite risk score with evidence-based reasoning.
"""
import concurrent.futures
import time
from env_config import load_env
from shodan_module import query_shodan_host
from virustotal_module import query_vt_ip, query_vt_hash
from abuseipdb_module import query_abuseipdb
from whois_module import query_whois

load_env()   # Load API

def investigate_ip(ip):
    """Query all IP intelligence sources in parallel"""
    start = time.time()
    # Map of task name -> callable with its argument
    tasks = {
        'shodan':    (query_shodan_host, ip),
        'virustotal':(query_vt_ip,       ip),
        'abuseipdb': (query_abuseipdb,   ip),
    }
    results = {}
    # Submit all tasks to thread pool simultaneously
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(fn, arg): name
            for name, (fn, arg) in tasks.items()
        }
        for future in concurrent.futures.as_completed(futures, timeout=20):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = {'error': str(e)}
    elapsed = round(time.time() - start, 2)
    results['_meta'] = {'target': ip, 'type': 'ip', 'query_time_s': elapsed}
    return results


# RISK SCORING ENGINE
def calculate_risk_score(results):
    """
    Aggregate signals from all API sources into a 0-100 risk score.
    Scoring model:
      +40 pts: VirusTotal malicious detections (scaled by detection rate)
      +25 pts: AbuseIPDB abuse confidence >= 50%
      +15 pts: AbuseIPDB confidence >= 20% (lower threshold)
      +20 pts: Shodan shows known vulnerabilities (CVEs)
      +15 pts: Shodan tags include 'compromised', 'malware', 'tor'
      +10 pts: Very recently registered domain (< 30 days)
      +10 pts: Is a Tor exit node / anonymous proxy
      -10 pts: Known legitimate service (Google, Cloudflare, Akamai ASN)
    """
    score = 0
    evidence = []
    shodan   = results.get('shodan', {})
    vt       = results.get('virustotal', {})
    abuse    = results.get('abuseipdb', {})

    # VirusTotal signals
    vt_stats = vt.get('detection_stats', {})
    malicious_count = vt_stats.get('malicious', 0)
    total_engines   = vt_stats.get('total_engines', 1)

    if malicious_count > 0:
        vt_contribution = min(40, int((malicious_count / total_engines) * 40))
        score += vt_contribution
        evidence.append(f'+{vt_contribution} VT: {malicious_count}/{total_engines} engines detect as malicious')

    # Negative VT reputation is also a signal
    vt_rep = vt.get('reputation', 0)
    if vt_rep < -10:
        score += 10
        evidence.append(f'+10 VT reputation score: {vt_rep} (negative = community flagged)')

    # AbuseIPDB signals
    abuse_confidence = abuse.get('abuse_confidence', 0)
    abuse_reports    = abuse.get('total_reports', 0)

    if abuse_confidence >= 50:
        score += 25
        evidence.append(f'+25 AbuseIPDB confidence: {abuse_confidence}% ({abuse_reports} reports)')
    elif abuse_confidence >= 20:
        score += 15
        evidence.append(f'+15 AbuseIPDB confidence: {abuse_confidence}% ({abuse_reports} reports)')

    # Shodan signals
    vulns = shodan.get('vulnerabilities', [])
    if vulns:
        score += 20
        evidence.append(f'+20 Shodan: {len(vulns)} known CVEs: {", ".join(vulns[:3])}')

    bad_tags = {'compromised', 'malware', 'tor', 'scanner', 'botnet'}
    shodan_tags = set(shodan.get('tags', []))
    matched_tags = bad_tags & shodan_tags
    if matched_tags:
        score += 15
        evidence.append(f'+15 Shodan tags: {", ".join(matched_tags)}')

    # Known-good signal (reduce false positives)
    good_asns = {'AS15169', 'AS13335', 'AS20940'}  # Google, Cloudflare, Akamai
    target_asn = shodan.get('asn', '').upper()
    if target_asn in good_asns:
        score = max(0, score - 10)
        evidence.append(f'-10 Known legitimate ASN: {target_asn}')

    # Final classification
    score = min(100, score)
    if   score >= 70: level, colour = 'CRITICAL', '🔴'
    elif score >= 40: level, colour = 'HIGH',     '🟠'
    elif score >= 20: level, colour = 'MEDIUM',   '🟡'
    else:              level, colour = 'LOW',     '🟢'

    return {
        'score':    score,
        'level':    level,
        'colour':   colour,
        'evidence': evidence
    }
