#!/usr/bin/env python3
"""
TLS Certificate & Domain Intelligence Inspector
Extracts TLS cert details, SANs, and discovers related domains via CT logs.
"""

import ssl
import socket
import json
import argparse
import sys
import datetime
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, NameOID


# ─── Certificate fetching ────────────────────────────────────────────────────

def fetch_cert(hostname: str, port: int = 443, timeout: int = 10) -> x509.Certificate:
    """Open a TLS connection and return the parsed X.509 certificate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want the cert even if invalid/expired

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
            der = tls.getpeercert(binary_form=True)

    return x509.load_der_x509_certificate(der)


# ─── Certificate parsing ─────────────────────────────────────────────────────

def _name_attr(name: x509.Name, oid) -> str:
    try:
        return name.get_attributes_for_oid(oid)[0].value
    except IndexError:
        return ""


def parse_subject(cert: x509.Certificate) -> dict:
    n = cert.subject
    return {
        "common_name":   _name_attr(n, NameOID.COMMON_NAME),
        "org":           _name_attr(n, NameOID.ORGANIZATION_NAME),
        "org_unit":      _name_attr(n, NameOID.ORGANIZATIONAL_UNIT_NAME),
        "country":       _name_attr(n, NameOID.COUNTRY_NAME),
        "state":         _name_attr(n, NameOID.STATE_OR_PROVINCE_NAME),
        "locality":      _name_attr(n, NameOID.LOCALITY_NAME),
        "email":         _name_attr(n, NameOID.EMAIL_ADDRESS),
    }


def parse_issuer(cert: x509.Certificate) -> dict:
    n = cert.issuer
    return {
        "common_name": _name_attr(n, NameOID.COMMON_NAME),
        "org":         _name_attr(n, NameOID.ORGANIZATION_NAME),
        "country":     _name_attr(n, NameOID.COUNTRY_NAME),
    }


def parse_validity(cert: x509.Certificate) -> dict:
    now = datetime.datetime.utcnow()
    not_before = cert.not_valid_before
    not_after  = cert.not_valid_after
    days_left  = (not_after - now).days
    return {
        "not_before":  not_before.isoformat() + "Z",
        "not_after":   not_after.isoformat() + "Z",
        "days_remaining": days_left,
        "is_expired":  days_left < 0,
        "expires_soon": 0 <= days_left <= 30,
    }


def parse_sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return [str(name.value) for name in ext.value]
    except x509.ExtensionNotFound:
        return []


def parse_key_info(cert: x509.Certificate) -> dict:
    pub = cert.public_key()
    raw = type(pub).__name__
    key_type = (raw.replace("_RSAPublicKey", "RSA")
                   .replace("_EllipticCurvePublicKey", "EC")
                   .replace("_DSAPublicKey", "DSA")
                   .replace("_Ed25519PublicKey", "Ed25519")
                   .replace("_Ed448PublicKey", "Ed448"))
    info = {"type": key_type}
    try:
        info["size_bits"] = pub.key_size
    except AttributeError:
        pass
    return info


def parse_extensions_summary(cert: x509.Certificate) -> dict:
    result = {}

    # Basic Constraints
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        result["is_ca"] = bc.value.ca
        result["path_length"] = bc.value.path_length
    except x509.ExtensionNotFound:
        result["is_ca"] = False

    # Key Usage
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        result["key_usage"] = [
            name for name, flag in {
                "digital_signature": ku.digital_signature,
                "content_commitment": ku.content_commitment,
                "key_encipherment": ku.key_encipherment,
                "key_agreement": ku.key_agreement,
                "key_cert_sign": ku.key_cert_sign,
                "crl_sign": ku.crl_sign,
            }.items() if flag
        ]
    except x509.ExtensionNotFound:
        pass

    # Extended Key Usage
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        result["extended_key_usage"] = [oid.dotted_string for oid in eku]
    except x509.ExtensionNotFound:
        pass

    # CRL Distribution Points
    try:
        crl = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        result["crl_urls"] = [
            point.full_name[0].value
            for point in crl
            if point.full_name
        ]
    except x509.ExtensionNotFound:
        pass

    # OCSP / AIA
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        result["ocsp_urls"] = [
            desc.access_location.value
            for desc in aia
            if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.1"
        ]
        result["issuer_cert_urls"] = [
            desc.access_location.value
            for desc in aia
            if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.2"
        ]
    except x509.ExtensionNotFound:
        pass

    return result


def fingerprints(cert: x509.Certificate) -> dict:
    return {
        "sha256": cert.fingerprint(hashes.SHA256()).hex(":"),
        "sha1":   cert.fingerprint(hashes.SHA1()).hex(":"),
    }


def full_cert_analysis(cert: x509.Certificate) -> dict:
    return {
        "subject":     parse_subject(cert),
        "issuer":      parse_issuer(cert),
        "validity":    parse_validity(cert),
        "serial":      str(cert.serial_number),
        "version":     cert.version.name,
        "key":         parse_key_info(cert),
        "sans":        parse_sans(cert),
        "extensions":  parse_extensions_summary(cert),
        "fingerprints": fingerprints(cert),
    }


# ─── Certificate Transparency log query (crt.sh) ─────────────────────────────

def query_ct_logs(domain: str, timeout: int = 15) -> list[dict]:
    """
    Query crt.sh (Certificate Transparency log aggregator) for all certs
    ever issued for a domain. Returns deduplicated list of cert metadata.
    """
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        resp = requests.get(url, params=params, timeout=timeout,
                            headers={"Accept": "application/json"})
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        return [{"error": str(e)}]
    except json.JSONDecodeError:
        return [{"error": "crt.sh returned non-JSON (rate limited or down)"}]


def extract_domains_from_ct(ct_entries: list[dict]) -> dict:
    all_names: set[str] = set()

    for entry in ct_entries:
        if "error" in entry:
            continue
        raw = entry.get("name_value", "")
        for name in raw.split("\n"):
            name = name.strip().lower()
            if name:
                all_names.add(name)

    wildcards  = sorted(n for n in all_names if n.startswith("*."))
    subdomains = sorted(n for n in all_names if "." in n and not n.startswith("*."))
    return {
        "total": len(all_names),
        "wildcards": wildcards,
        "domains": subdomains,
    }


def ct_log_summary(ct_entries: list[dict]) -> list[dict]:
    seen: set[str] = set()
    certs = []
    for e in ct_entries:
        if "error" in e:
            continue
        fp = e.get("id", "")
        if fp in seen:
            continue
        seen.add(fp)
        certs.append({
            "id":          e.get("id"),
            "logged_at":   e.get("entry_timestamp", ""),
            "not_before":  e.get("not_before", ""),
            "not_after":   e.get("not_after", ""),
            "common_name": e.get("common_name", ""),
            "issuer":      e.get("issuer_name", ""),
            "name_count":  len(e.get("name_value", "").split("\n")),
        })
    certs.sort(key=lambda c: c.get("logged_at", ""), reverse=True)
    return certs[:50]


# ─── Threat/risk signals ─────────────────────────────────────────────────────

KNOWN_FREE_CAS = {"let's encrypt", "zerossl", "buypass"}

def risk_signals(cert_data: dict, ct_domains: dict) -> list[str]:
    signals = []
    v = cert_data["validity"]

    if v["is_expired"]:
        signals.append("EXPIRED certificate — server may be misconfigured")
    elif v["expires_soon"]:
        signals.append(f"Cert expires in {v['days_remaining']} days — expiry imminent")

    issuer_org = cert_data["issuer"]["org"].lower()
    if any(ca in issuer_org for ca in KNOWN_FREE_CAS):
        signals.append(f"Free CA ({cert_data['issuer']['org']}) — common in phishing infra")

    sans = cert_data["sans"]
    if len(sans) == 1:
        signals.append("Single-SAN cert — narrow scope, may be purpose-built")
    elif len(sans) > 50:
        signals.append(f"Very broad cert ({len(sans)} SANs) — shared hosting or CDN")

    if cert_data["extensions"].get("is_ca"):
        signals.append("Certificate is a CA — can sign other certs (intermediate/root)")

    wildcards = ct_domains.get("wildcards", [])
    if wildcards:
        signals.append(f"{len(wildcards)} wildcard SAN(s) found in CT logs — broad domain coverage")

    if ct_domains.get("total", 0) > 200:
        signals.append(f"Large CT footprint ({ct_domains['total']} names) — extensive subdomain presence")

    return signals


# ─── Output formatting ────────────────────────────────────────────────────────

def _section(title: str) -> str:
    bar = "─" * (60 - len(title) - 3)
    return f"\n\033[1;36m── {title} {bar}\033[0m"

def _kv(key: str, val, indent: int = 2) -> str:
    pad = " " * indent
    if val == "" or val is None:
        return ""
    return f"{pad}\033[33m{key:<22}\033[0m {val}"


def print_report(hostname: str, cert_data: dict, ct_entries: list[dict],
                 ct_domains: dict, signals: list[str]) -> None:
    print(f"\n\033[1;35m{'═'*64}\033[0m")
    print(f"\033[1;35m  TLS CERTIFICATE INTELLIGENCE REPORT\033[0m")
    print(f"\033[1;35m  Target: {hostname}\033[0m")
    print(f"\033[1;35m{'═'*64}\033[0m")

    print(_section("SUBJECT (Who the cert is for)"))
    for k, v in cert_data["subject"].items():
        if line := _kv(k, v): print(line)

    print(_section("ISSUER (Certificate Authority)"))
    for k, v in cert_data["issuer"].items():
        if line := _kv(k, v): print(line)

    print(_section("VALIDITY"))
    v = cert_data["validity"]
    status = "\033[31mEXPIRED\033[0m" if v["is_expired"] else (
             "\033[33mEXPIRES SOON\033[0m" if v["expires_soon"] else "\033[32mVALID\033[0m")
    print(_kv("status", status))
    print(_kv("not_before", v["not_before"]))
    print(_kv("not_after", v["not_after"]))
    print(_kv("days_remaining", v["days_remaining"]))

    print(_section("KEY & FINGERPRINTS"))
    k = cert_data["key"]
    print(_kv("key_type", k["type"]))
    if "size_bits" in k:
        print(_kv("key_size", f"{k['size_bits']} bits"))
    print(_kv("serial", cert_data["serial"][:32] + "..."))
    print(_kv("version", cert_data["version"]))
    fp = cert_data["fingerprints"]
    print(_kv("sha256", fp["sha256"][:47] + "..."))
    print(_kv("sha1",   fp["sha1"]))

    print(_section(f"SUBJECT ALTERNATIVE NAMES ({len(cert_data['sans'])})"))
    for san in cert_data["sans"]:
        print(f"    \033[32m{san}\033[0m")

    ext = cert_data["extensions"]
    print(_section("EXTENSIONS"))
    print(_kv("is_ca", ext.get("is_ca", False)))
    if "key_usage" in ext:
        print(_kv("key_usage", ", ".join(ext["key_usage"])))
    for u in ext.get("ocsp_urls", []):
        print(_kv("ocsp", u))
    for u in ext.get("crl_urls", []):
        print(_kv("crl", u))

    print(_section(f"CT LOG DOMAINS ({ct_domains.get('total', 0)} unique names)"))
    wildcards = ct_domains.get("wildcards", [])
    domains   = ct_domains.get("domains", [])
    if wildcards:
        print("  \033[33mWildcards:\033[0m")
        for w in wildcards[:20]: print(f"    \033[33m{w}\033[0m")
        if len(wildcards) > 20: print(f"    ... and {len(wildcards)-20} more")
    if domains:
        print("  \033[32mDomains/Subdomains:\033[0m")
        for d in domains[:40]: print(f"    {d}")
        if len(domains) > 40: print(f"    ... and {len(domains)-40} more")

    ct_certs = ct_log_summary(ct_entries)
    print(_section(f"CT LOG CERTIFICATE HISTORY (recent {len(ct_certs)})"))
    for c in ct_certs[:10]:
        issuer_s = c["issuer"].split("O=")[-1].split(",")[0][:30] if "O=" in c["issuer"] else c["issuer"][:30]
        print(f"  {c['not_before'][:10]}  \033[32m{c['common_name']:<35}\033[0m  {issuer_s}  [{c['name_count']} names]")
    if len(ct_certs) > 10:
        print(f"  ... {len(ct_certs)-10} more certs in history")

    if signals:
        print(_section("ANALYST SIGNALS"))
        for sig in signals:
            prefix = "\033[31m[!]\033[0m" if any(w in sig for w in ["EXPIRED", "phishing", "misconfigured"]) else "\033[33m[~]\033[0m"
            print(f"  {prefix} {sig}")

    print(f"\n\033[1;35m{'═'*64}\033[0m\n")


# ─── Entry point ─────────────────────────────────────────────────────────────

def resolve_host(url_or_host: str) -> tuple[str, int]:
    if "://" not in url_or_host:
        url_or_host = "https://" + url_or_host
    parsed = urlparse(url_or_host)
    return parsed.hostname, parsed.port or 443


def main():
    parser = argparse.ArgumentParser(
        description="TLS Certificate & Domain Intelligence Inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 tls_inspector.py github.com
  python3 tls_inspector.py https://www.google.com
  python3 tls_inspector.py example.com --no-ct
  python3 tls_inspector.py example.com --json
  python3 tls_inspector.py example.com --port 8443
        """
    )
    parser.add_argument("target",    help="Hostname, domain, or URL to inspect")
    parser.add_argument("--port",    type=int, default=443, help="TLS port (default: 443)")
    parser.add_argument("--no-ct",   action="store_true",   help="Skip CT log query")
    parser.add_argument("--json",    action="store_true",   help="Output raw JSON")
    parser.add_argument("--timeout", type=int, default=10,  help="Connection timeout seconds")
    args = parser.parse_args()

    host, port = resolve_host(args.target)
    if args.port != 443:
        port = args.port

    print(f"  Connecting to {host}:{port} ...", end="", flush=True)
    try:
        cert = fetch_cert(host, port, timeout=args.timeout)
    except Exception as e:
        print(f"\n  ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    print(" done")

    cert_data = full_cert_analysis(cert)
    ct_entries: list[dict] = []
    ct_domains: dict = {"total": 0, "wildcards": [], "domains": []}

    if not args.no_ct:
        apex = ".".join(host.split(".")[-2:])
        print(f"  Querying crt.sh CT logs for *.{apex} ...", end="", flush=True)
        ct_entries = query_ct_logs(apex, timeout=args.timeout + 5)
        ct_domains = extract_domains_from_ct(ct_entries)
        err = next((e["error"] for e in ct_entries if "error" in e), None)
        print(f" {ct_domains.get('total', 0)} names found" if not err else f" error: {err}")

    signals = risk_signals(cert_data, ct_domains)

    if args.json:
        print(json.dumps({
            "target": host,
            "certificate": cert_data,
            "ct_log_domains": ct_domains,
            "ct_log_history": ct_log_summary(ct_entries),
            "analyst_signals": signals,
        }, indent=2))
    else:
        print_report(host, cert_data, ct_entries, ct_domains, signals)


if __name__ == "__main__":
    main()


