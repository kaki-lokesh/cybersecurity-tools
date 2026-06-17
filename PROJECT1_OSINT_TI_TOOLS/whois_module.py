import whois  

def query_whois(domain):
    """Query WHOIS data for a domain. Returns structured dict"""
    try:
        w = whois.whois(domain)
        # Dates may be lists (multiple WHOIS servers return different values)
        def normalise_date(d):
            if isinstance(d, list): return str(d[0]) if d else None
            return str(d) if d else None
        return {
            'source':        'WHOIS',
            'domain':        w.domain_name,
            'registrar':     w.registrar,
            'creation_date': normalise_date(w.creation_date),
            'expiry_date':   normalise_date(w.expiration_date),
            'updated_date':  normalise_date(w.updated_date),
            'status':        w.status,
            'name_servers':  w.name_servers,
            'emails':        w.emails,
            'country':       w.country,
        }
    except Exception as e:
        return {'source': 'WHOIS', 'error': str(e)}