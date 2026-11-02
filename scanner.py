"""Subdomain discovery (public certificate logs) and live SSL certificate checks."""
import ipaddress
import json
import math
import os
import random
import re
import socket
import ssl
import string
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

# ----------------------------------------------------------------- settings
SCAN_PORT = int(os.getenv("SCAN_PORT", "443"))
SCAN_WORKERS = int(os.getenv("SCAN_WORKERS", "20"))
CONNECT_TIMEOUT = float(os.getenv("CONNECT_TIMEOUT", "6"))
MAX_HOSTS = int(os.getenv("MAX_HOSTS", "500"))
LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", "90"))  # also look at certs that expired this recently
ALLOW_PRIVATE_TARGETS = os.getenv("ALLOW_PRIVATE_TARGETS", "0") == "1"  # keep off in production
CRITICAL_DAYS = 7
WARNING_DAYS = 30
USER_AGENT = "ssl-expiry-scanner/1.0 (+certificate expiry monitoring)"

COMMON_SUBDOMAINS = """www mail webmail smtp imap pop ftp sftp vpn api dev test staging stage qa uat beta
demo admin portal app apps blog shop store cdn static assets img media docs help support status m mobile
login sso auth id git gitlab jenkins grafana monitor intranet remote mx autodiscover cpanel dashboard
crm erp files download secure pay payments careers jobs news""".split()

HOST_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
)


class DiscoveryError(Exception):
    pass


class ScanError(Exception):
    pass


# ------------------------------------------------------------ input helpers
def normalize_domain(raw: str) -> str:
    """Turn whatever the user typed (URL, host:port, with www) into a bare domain."""
    s = (raw or "").strip().lower()
    if not s:
        raise ValueError("Enter a website address, for example example.com.")
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = re.split(r"[/?#]", s, maxsplit=1)[0]
    s = s.rsplit("@", 1)[-1]
    s = re.sub(r":\d+$", "", s).strip(".")
    if s.startswith("www."):
        s = s[4:]
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("That doesn't look like a valid domain name.")
    is_ip = False
    try:
        ipaddress.ip_address(s)
        is_ip = True
    except ValueError:
        pass
    if is_ip:
        raise ValueError("Enter a domain name such as example.com, not an IP address.")
    if "." not in s or not HOST_RE.match(s):
        raise ValueError("That doesn't look like a valid domain name. Try something like example.com.")
    return s


def _clean_names(raw_names, domain):
    """Keep only valid hostnames at or under `domain`. Wildcards become their base name."""
    out = set()
    for n in raw_names:
        n = n.strip().lower().rstrip(".")
        if n.startswith("*."):
            n = n[2:]
        if not n or "@" in n or " " in n:
            continue
        if (n == domain or n.endswith("." + domain)) and HOST_RE.match(n):
            out.add(n)
    return out


# --------------------------------------------------------- discovery sources
def _recent_enough(not_after_str):
    if not not_after_str:
        return True
    try:
        dt = datetime.fromisoformat(not_after_str.replace("Z", "")).replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    return dt >= datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)


def _from_crtsh(domain):
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    last = None
    for attempt in range(3):
        try:
            with requests.get(url, params=params, timeout=(10, 60), stream=True,
                              headers={"User-Agent": USER_AGENT}) as r:
                if r.status_code != 200:
                    raise DiscoveryError(f"crt.sh answered HTTP {r.status_code}")
                body, size = [], 0
                for chunk in r.iter_content(65536):
                    size += len(chunk)
                    if size > 40 * 1024 * 1024:
                        raise DiscoveryError("crt.sh returned too much data for this domain")
                    body.append(chunk)
            rows = json.loads(b"".join(body) or b"[]")
            names = []
            for row in rows:
                if _recent_enough(row.get("not_after")):
                    names.extend(str(row.get("name_value", "")).split("\n"))
            return names
        except (requests.RequestException, ValueError, DiscoveryError) as e:
            last = e
            time.sleep(1.5 * (attempt + 1))
    raise DiscoveryError(f"crt.sh unavailable ({last})")


def _from_certspotter(domain):
    url = "https://api.certspotter.com/v1/issuances"
    names, after = [], None
    for _ in range(10):  # up to 10 pages
        params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
        if after:
            params["after"] = after
        try:
            r = requests.get(url, params=params, timeout=30, headers={"User-Agent": USER_AGENT})
        except requests.RequestException as e:
            raise DiscoveryError(f"Cert Spotter unavailable ({e})")
        if r.status_code == 429:
            break  # rate limited: use what we have
        if r.status_code != 200:
            raise DiscoveryError(f"Cert Spotter answered HTTP {r.status_code}")
        page = r.json()
        if not page:
            break
        for item in page:
            if _recent_enough(item.get("not_after")):
                names.extend(item.get("dns_names", []))
        after = page[-1].get("id")
        if len(page) < 100:
            break
    return names


def _dns_probe(domain):
    """Resolve common subdomain names. Skipped when the domain has wildcard DNS."""
    def resolves(host):
        try:
            socket.getaddrinfo(host, None)
            return True
        except OSError:
            return False

    junk = "".join(random.choices(string.ascii_lowercase, k=14))
    if resolves(f"{junk}.{domain}"):
        return [], "Wildcard DNS detected, so the common-name probe was skipped."
    hosts = [f"{p}.{domain}" for p in COMMON_SUBDOMAINS]
    with ThreadPoolExecutor(16) as ex:
        hits = [h for h, ok in zip(hosts, ex.map(resolves, hosts)) if ok]
    return hits, None


def discover(domain, deep=False):
    """Return ({host: {sources}}, [warnings])."""
    found, warnings = {}, []

    def add(names, source):
        for n in _clean_names(names, domain):
            found.setdefault(n, set()).add(source)

    add([domain, f"www.{domain}"], "entered")
    ct_names = None
    for label, fn in (("crt.sh", _from_crtsh), ("Cert Spotter", _from_certspotter)):
        try:
            ct_names = fn(domain)
            add(ct_names, label)
            if ct_names:
                break
        except DiscoveryError as e:
            warnings.append(f"{e}.")
    if ct_names is None:
        warnings.append("Public certificate logs could not be reached, so only the main domain and www were checked.")
    if deep:
        hits, note = _dns_probe(domain)
        add(hits, "DNS guess")
        if note:
            warnings.append(note)
    return found, warnings


# ------------------------------------------------------------ live TLS check
def _resolve_targets(host):
    try:
        infos = socket.getaddrinfo(host, SCAN_PORT, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ScanError("No DNS record")
    ips = sorted({ipaddress.ip_address(i[4][0]) for i in infos}, key=lambda a: a.version)
    if not ips:
        raise ScanError("No DNS record")
    if not ALLOW_PRIVATE_TARGETS:
        ips = [i for i in ips if i.is_global]
        if not ips:
            raise ScanError("Points to a private address (skipped for safety)")
    return [str(i) for i in ips]


def _handshake(ip, host, ctx):
    with socket.create_connection((ip, SCAN_PORT), timeout=CONNECT_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            return s.getpeercert(binary_form=True)


def _name_attr(name, oid):
    try:
        vals = name.get_attributes_for_oid(oid)
        return vals[0].value if vals else ""
    except Exception:
        return ""


def check_host(host):
    """Connect to host:443 and return a result dict (never raises)."""
    res = {"host": host, "status": "error", "days_left": None, "expires_at": None, "issued_at": None,
           "issuer": "", "common_name": "", "ip": "", "trusted": None, "trust_error": "", "error": ""}
    try:
        ips = _resolve_targets(host)
        res["ip"] = ips[0]
        raw_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        raw_ctx.check_hostname = False
        raw_ctx.verify_mode = ssl.CERT_NONE
        der, last = None, None
        for ip in ips[:2]:
            try:
                der = _handshake(ip, host, raw_ctx)
                res["ip"] = ip
                break
            except Exception as e:  # try next address
                last = e
        if der is None:
            raise last

        cert = x509.load_der_x509_certificate(der)
        not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
        days = (not_after - datetime.now(timezone.utc)).total_seconds() / 86400
        days_left = math.floor(days)  # 5.3 days left -> 5; expired 0.3 days ago -> -1
        res.update(
            expires_at=not_after.isoformat(), issued_at=not_before.isoformat(), days_left=days_left,
            issuer=_name_attr(cert.issuer, NameOID.ORGANIZATION_NAME) or _name_attr(cert.issuer, NameOID.COMMON_NAME),
            common_name=_name_attr(cert.subject, NameOID.COMMON_NAME),
            fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
        )
        res["status"] = ("expired" if days_left < 0 else "critical" if days_left <= CRITICAL_DAYS
                         else "warning" if days_left <= WARNING_DAYS else "ok")

        # Second handshake with full verification: is the certificate trusted for this hostname?
        try:
            _handshake(res["ip"], host, ssl.create_default_context())
            res["trusted"] = True
        except ssl.SSLCertVerificationError as e:
            res["trusted"], res["trust_error"] = False, e.verify_message
        except Exception as e:
            res["trusted"], res["trust_error"] = None, str(e)
    except ScanError as e:
        res["error"] = str(e)
    except socket.timeout:
        res["error"] = "Connection timed out"
    except ConnectionRefusedError:
        res["error"] = f"Port {SCAN_PORT} is closed (no SSL)"
    except ssl.SSLError as e:
        res["error"] = f"TLS error: {e.reason or e}"
    except OSError as e:
        res["error"] = f"Could not connect: {e.strerror or e}"
    except Exception as e:  # certificate parsing etc.
        res["error"] = f"Unexpected error: {e}"
    return res


def sort_results(rows):
    """Soonest expiry first (expired on top); hosts without a certificate go last."""
    return sorted(rows, key=lambda r: (r["expires_at"] is None, r["expires_at"] or "", r["host"]))


def summarize(rows):
    out = {"total": len(rows), "expired": 0, "critical": 0, "warning": 0, "ok": 0, "error": 0}
    for r in rows:
        out[r["status"]] += 1
    return out


# ------------------------------------------------------------------- jobs
class Job:
    def __init__(self, domain, deep):
        self.id = uuid.uuid4().hex
        self.domain, self.deep = domain, deep
        self.phase = "queued"  # queued, discovering, scanning, done, failed
        self.total = self.done = 0
        self.results, self.warnings = [], []
        self.error = ""
        self.created = time.time()
        self.finished = None
        self.lock = threading.Lock()

    def snapshot(self):
        with self.lock:
            rows = sort_results(self.results)
            return {
                "id": self.id, "domain": self.domain, "phase": self.phase, "total": self.total,
                "done": self.done, "warnings": list(self.warnings), "error": self.error,
                "results": rows, "summary": summarize(rows),
                "finished_at": datetime.fromtimestamp(self.finished, timezone.utc).isoformat() if self.finished else None,
            }


class JobManager:
    def __init__(self, max_running=3, ttl=3600):
        self.jobs, self.lock = {}, threading.Lock()
        self.max_running, self.ttl = max_running, ttl

    def _purge(self):
        now = time.time()
        for jid in [j for j, job in self.jobs.items() if now - job.created > self.ttl]:
            del self.jobs[jid]

    def running(self):
        return sum(1 for j in self.jobs.values() if j.phase in ("queued", "discovering", "scanning"))

    def start(self, domain, deep):
        with self.lock:
            self._purge()
            if self.running() >= self.max_running:
                return None
            job = Job(domain, deep)
            self.jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def get(self, job_id):
        with self.lock:
            return self.jobs.get(job_id)

    def _run(self, job):
        try:
            job.phase = "discovering"
            found, warnings = discover(job.domain, job.deep)
            hosts = sorted(found, key=lambda h: (h != job.domain, h))
            if len(hosts) > MAX_HOSTS:
                warnings.append(f"Found {len(hosts)} hostnames; only the first {MAX_HOSTS} were checked.")
                hosts = hosts[:MAX_HOSTS]
            with job.lock:
                job.warnings, job.total, job.phase = warnings, len(hosts), "scanning"
            with ThreadPoolExecutor(SCAN_WORKERS) as ex:
                futures = {ex.submit(check_host, h): h for h in hosts}
                for f in as_completed(futures):
                    r = f.result()
                    r["sources"] = sorted(found[r["host"]])
                    with job.lock:
                        job.results.append(r)
                        job.done += 1
            job.finished = time.time()
            job.phase = "done"
        except Exception as e:  # keep the UI informed instead of hanging
            job.error, job.phase = f"Scan failed: {e}", "failed"
            job.finished = time.time()
