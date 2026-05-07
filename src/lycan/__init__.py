#!/usr/bin/env python3
"""
Lycan Local Scan Agent (BYOI)
------------------------------------------------------------
- Supabase Realtime subscription for zero-latency job pickup
- Claims pending jobs atomically via scan_jobs INSERT events
- Executes security modules against target
- Captures full HTTP evidence (headers + body sample) on findings
- Sends heartbeat every 60s to agents table (independent thread)
- Enumerates all active network interfaces for rich metadata
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import pathlib
import platform
import re
import signal
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlparse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from packaging import version
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError
from supabase import Client, create_client
from supabase.lib.client_options import ClientOptions
from rich.console import Console
from rich.text import Text
from rich.rule import Rule
from rich.panel import Panel
from rich.table import Table
from rich import box

try:
    import netifaces  # type: ignore
    _HAS_NETIFACES = True
except ImportError:
    _HAS_NETIFACES = False


__version__ = "1.1.0"
REPO_URL = "https://api.github.com/repos/unkn0wn-ap/lycan-cli/releases/latest"

def check_for_updates(silent=True) -> Optional[str]:
    """Check GitHub API for new versions"""
    try:
        response = requests.get(REPO_URL, timeout=5)
        if response.status_code == 200:
            latest_release = response.json()
            remote_version = latest_release.get('tag_name', '').replace('v', '')
            
            if remote_version and version.parse(remote_version) > version.parse(__version__):
                print(f"\n[!] New version available: v{remote_version}. Run 'lycan update' to upgrade.")
                return remote_version
    except Exception:
        pass 
    return None

def exec_update() -> None:
    """Upgrade logic: Download and install the new version from GitHub"""
    print("[*] Starting Lycan Agent update...")
    try:
        # 1. Re-run the install script directly from GitHub
        install_url = "https://raw.githubusercontent.com/unkn0wn-ap/lycan-cli/main/install.sh"
        cmd = f"curl -sSL {install_url} | bash"
        subprocess.check_call(cmd, shell=True)
        
        print("[\u2713] Package updated successfully.")
        
        # 2. Attempt to restart or exit
        lycan_bin = shutil.which("lycan")
        if lycan_bin:
            print("[*] Restarting...")
            os.execv(lycan_bin, ['lycan'] + sys.argv[1:])
        else:
            print("[!] Update complete. Please restart the agent manually.")
            sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Update failed: {e}")
        print("[!] Please try manual update: curl -sSL https://raw.githubusercontent.com/unkn0wn-ap/lycan-cli/main/install.sh | bash")


# ─── Config file: ~/.lycan/config.json ─────────────────────────────────────────────────

_CONFIG_PATH = pathlib.Path.home() / ".lycan" / "config.json"


def load_config() -> Dict[str, str]:
    """
    Load ~/.lycan/config.json and return its contents as a dict.
    Non-empty values are injected into os.environ so Settings can pick them up.
    If the file doesn't exist or is malformed, returns an empty dict silently.
    """
    if not _CONFIG_PATH.exists():
        return {}
    try:
        raw = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return {}
        env_map = {
            "lycan_api_key":             "LYCAN_API_KEY",
            "supabase_url":              "SUPABASE_URL",
            "supabase_anon_key":         "SUPABASE_ANON_KEY",
            "worker_id":                 "WORKER_ID",
            "agent_mode":                "AGENT_MODE",
            "heartbeat_interval_seconds": "HEARTBEAT_INTERVAL_SECONDS",
        }
        for key, env_var in env_map.items():
            val = str(raw.get(key, "")).strip()
            if val and not os.environ.get(env_var):
                os.environ[env_var] = val
        return raw
    except Exception:
        return {}


def save_config(data: Dict[str, Any]) -> None:
    """Persist a config dict to ~/.lycan/config.json with 0600 permissions."""
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    _CONFIG_PATH.chmod(0o600)


class Settings(BaseModel):
    supabase_url: str = Field(default_factory=lambda: os.getenv("SUPABASE_URL", "https://yjudriersfjxayinzpng.supabase.co"))
    supabase_anon_key: str = Field(default_factory=lambda: os.getenv("SUPABASE_ANON_KEY", "sb_publishable_Yoy8N4jPqC-Etc0gmm8r9g_0ipwfiBJ"))
    lycan_api_key: str = Field(default_factory=lambda: os.getenv("LYCAN_API_KEY", ""))
    poll_interval_seconds: int = Field(default_factory=lambda: int(os.getenv("AGENT_POLL_INTERVAL", "10")))
    heartbeat_interval_seconds: int = Field(default_factory=lambda: int(os.getenv("HEARTBEAT_INTERVAL_SECONDS", "60")))
    nmap_timeout_seconds: int = Field(default_factory=lambda: int(os.getenv("NMAP_TIMEOUT_SECONDS", "600")))
    worker_id: str = Field(default_factory=lambda: os.getenv("WORKER_ID", platform.node() or f"{socket.gethostname()}-{os.getpid()}"))
    agent_version: str = Field(default_factory=lambda: os.getenv("AGENT_VERSION", "1.1.0"))
    request_timeout_seconds: int = Field(default_factory=lambda: int(os.getenv("REQUEST_TIMEOUT_SECONDS", "8")))
    agent_mode: str = Field(default_factory=lambda: os.getenv("AGENT_MODE", "VERBOSE").upper())


def setup_logging(agent_mode: str = "VERBOSE") -> None:
    level = logging.ERROR if agent_mode == "SILENT" else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | [lycan-agent] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ─── Rich Console (singleton) ─────────────────────────────────────────────────

_console = Console(highlight=False)

_SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "bold orange1",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim white",
}


class AgentConsole:
    """Thin wrapper around Rich console respecting AGENT_MODE."""

    def __init__(self, mode: str = "VERBOSE") -> None:
        # VERBOSE → full output | SILENT → errors only
        self.verbose = mode != "SILENT"

    # ── Banner ────────────────────────────────────────────────────────────────
    def display_banner(self, version: str, worker_id: str) -> None:
        ascii_art = r"""
  _  __  ___   _   _   ___   _  _   
 | |/ / |_ _| | | | | / __| | \| |  
 | ' <   | |  | |_| || (__  | .` |  
  \_/\_\ |_|   \__, | \___| |_|\_|  
  __  __  ___   |___/ __  _ _  ___ 
 / _|/ _||  _| / __| | || | | | _ \
|__ \\__ \| _| | (__  | |_| | |  _/
|___/|___/|___|  \___|  \___/  |_|  
"""
        _console.print()
        _console.print(Text(ascii_art, style="bold magenta"))
        _console.print(
            Panel(
                f"[bold white]v{version}[/bold white]  ·  worker [cyan]{worker_id}[/cyan]",
                subtitle="[dim]lycan-security-agent[/dim]",
                border_style="magenta",
                box=box.ROUNDED,
                expand=False,
            )
        )
        _console.print()

    # ── Heartbeat ─────────────────────────────────────────────────────────────
    def log_heartbeat(self, worker_id: str) -> None:
        if not self.verbose:
            return
        _console.print(
            f"[bold green]♥  Heartbeat[/bold green]  "
            f"[dim]{now_iso()}[/dim]  worker=[cyan]{worker_id}[/cyan]"
        )

    # ── Module start ──────────────────────────────────────────────────────────
    def log_module_start(self, module_id: str, target: str, pct: int) -> None:
        if not self.verbose:
            return
        _console.print(
            f"[bold yellow]▶  [{pct:>3}%] Module:[/bold yellow] "
            f"[yellow]{module_id}[/yellow]  target=[dim]{target}[/dim]"
        )

    # ── Vulnerability detected ────────────────────────────────────────────────
    def log_vuln(self, module_id: str, severity: str, title: str, target: str) -> None:
        color = _SEVERITY_COLOR.get(severity, "white")
        sev_tag = f"[{color}]{severity.upper()}[/{color}]"
        _console.print(
            Rule(
                f"[!] VULN DETECTADA  {sev_tag}  [{color}]{title}[/{color}]",
                style=color,
            )
        )
        _console.print(
            f"    [dim]Module:[/dim] [bold]{module_id}[/bold]  "
            f"[dim]Target:[/dim] [underline]{target}[/underline]"
        )

    # ── Critical evidence (sqlmap banner/db) ──────────────────────────────────
    def log_critical_evidence(self, evidence: Dict[str, Any]) -> None:
        if not evidence:
            return
        tbl = Table(
            title="[bold red]⚠  CRITICAL EVIDENCE — SQLi Confirmed[/bold red]",
            box=box.SIMPLE_HEAVY,
            border_style="red",
            show_header=True,
            header_style="bold red",
        )
        tbl.add_column("Field", style="bold white", no_wrap=True)
        tbl.add_column("Value", style="red")
        if evidence.get("sqlmap_banner"):
            tbl.add_row("DB Banner", str(evidence["sqlmap_banner"]))
        if evidence.get("sqlmap_current_db"):
            tbl.add_row("Current DB", str(evidence["sqlmap_current_db"]))
        if evidence.get("confirmed_at"):
            tbl.add_row("Confirmed at", str(evidence["confirmed_at"]))
        _console.print(tbl)
        if evidence.get("sqlmap_raw_output") and self.verbose:
            _console.print(
                Panel(
                    evidence["sqlmap_raw_output"][:1500],
                    title="[red]sqlmap raw output (truncated)[/red]",
                    border_style="dim red",
                    expand=False,
                )
            )

    # ── Generic error ─────────────────────────────────────────────────────────
    def log_error(self, message: str) -> None:
        _console.print(f"[bold red]✗  ERROR:[/bold red] {message}")

    # ── Scan summary ──────────────────────────────────────────────────────────
    def log_scan_complete(
        self, job_id: str, target: str, score: int, findings_count: int
    ) -> None:
        if not self.verbose:
            return
        color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        _console.print(
            Panel(
                f"[bold {color}]Score: {score}/100[/bold {color}]  "
                f"Findings: [white]{findings_count}[/white]  "
                f"Target: [dim]{target}[/dim]",
                title=f"[bold green]✓ Scan Complete[/bold green]  job=[cyan]{job_id[:8]}…[/cyan]",
                border_style=color,
                box=box.ROUNDED,
                expand=False,
            )
        )


# Module-level console instance — replaced by run() after Settings are loaded
_agent_console: AgentConsole = AgentConsole(mode="VERBOSE")



def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Public-IP probe endpoints (tried in order; first success wins)
_PUBLIC_IP_ENDPOINTS = [
    "https://api.ipify.org",
    "https://api4.my-ip.io/ip",
    "https://checkip.amazonaws.com",
]


def get_public_ip(timeout_seconds: int = 5) -> Optional[str]:
    """
    Attempt to resolve the public IP via multiple fallback endpoints.
    Returns None (never raises) so closed/air-gapped networks don't block startup.
    """
    for endpoint in _PUBLIC_IP_ENDPOINTS:
        try:
            req = urllib.request.Request(
                endpoint,
                headers={"User-Agent": "Lycan-Agent/1.1"},
            )
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                ip = resp.read().decode("utf-8").strip()
                # Basic sanity check: looks like an IPv4 address
                parts = ip.split(".")
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    return ip
        except Exception:
            continue  # Try next endpoint silently

    logging.warning(
        "get_public_ip: all endpoints failed (no external connectivity?). "
        "Agent will continue with public_ip=None."
    )
    return None


def _get_interfaces_netifaces() -> List[Dict[str, str]]:
    """Enumerate interfaces using netifaces (cross-platform)."""
    interfaces: List[Dict[str, str]] = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        inet = addrs.get(netifaces.AF_INET, [])
        for addr in inet:
            ip = addr.get("addr", "")
            netmask = addr.get("netmask", "255.255.255.0")
            if not ip or ip.startswith("127."):
                continue
            try:
                net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                cidr = str(net)
            except Exception:
                cidr = f"{ip}/24"
            interfaces.append({"name": iface, "ip": ip, "cidr": cidr})
    return interfaces


def _get_interfaces_fallback() -> List[Dict[str, str]]:
    """Fallback: parse 'ip addr show' on Linux or 'ipconfig' on Windows."""
    interfaces: List[Dict[str, str]] = []
    system = platform.system()
    try:
        if system == "Linux":
            out = subprocess.check_output(
                ["ip", "-o", "-f", "inet", "addr", "show"], timeout=5
            ).decode(errors="replace")
            for line in out.splitlines():
                parts = line.split()
                # format: 2: eth0    inet 192.168.1.10/24 ...
                if len(parts) >= 4 and "/" in parts[3]:
                    iface = parts[1].rstrip(":")
                    cidr_str = parts[3]
                    ip = cidr_str.split("/")[0]
                    if ip.startswith("127."):
                        continue
                    try:
                        net = ipaddress.IPv4Interface(cidr_str).network
                        cidr = str(net)
                    except Exception:
                        cidr = cidr_str
                    interfaces.append({"name": iface, "ip": ip, "cidr": cidr})
        elif system == "Windows":
            out = subprocess.check_output(
                ["ipconfig"], timeout=5
            ).decode(errors="replace", encoding="oem")
            current_iface = "unknown"
            for line in out.splitlines():
                stripped = line.strip()
                if stripped.endswith(":") and not stripped.startswith(" "):
                    current_iface = stripped.rstrip(":")
                elif "IPv4" in stripped or "IP Address" in stripped:
                    ip = stripped.split(":")[-1].strip()
                    if ip and not ip.startswith("127."):
                        interfaces.append({"name": current_iface, "ip": ip, "cidr": f"{ip}/24"})
    except Exception:
        pass
    return interfaces


def get_local_context() -> Dict[str, Any]:
    """Return local IP, subnet mask and all active network interfaces."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "unknown"

    subnet_mask = "255.255.255.0"

    if _HAS_NETIFACES:
        interfaces = _get_interfaces_netifaces()
    else:
        interfaces = _get_interfaces_fallback()

    # Derive subnet_mask from the primary interface entry
    for iface in interfaces:
        if iface["ip"] == local_ip:
            try:
                net = ipaddress.IPv4Network(iface["cidr"], strict=False)
                subnet_mask = str(net.netmask)
            except Exception:
                pass
            break

    return {
        "local_ip": local_ip,
        "subnet_mask": subnet_mask,
        "interfaces": interfaces,
    }


def is_in_local_subnet(target: str) -> bool:
    try:
        target_ip = socket.gethostbyname(target)
        target_obj = ipaddress.IPv4Address(target_ip)
        ctx = get_local_context()
        # Check against ALL known local subnets
        for iface in ctx.get("interfaces", []):
            try:
                network = ipaddress.IPv4Network(iface["cidr"], strict=False)
                if target_obj in network:
                    return True
            except Exception:
                continue
        # Fallback: primary subnet
        if ctx["local_ip"] != "unknown" and ctx["subnet_mask"] != "unknown":
            network = ipaddress.IPv4Network(f"{ctx['local_ip']}/{ctx['subnet_mask']}", strict=False)
            return target_obj in network
    except Exception:
        pass
    return False


def build_client(settings: Settings) -> Client:
    if not settings.supabase_url:
        raise RuntimeError("SUPABASE_URL is required.")
    if not settings.supabase_anon_key:
        raise RuntimeError("SUPABASE_ANON_KEY is required.")
    if not settings.lycan_api_key:
        raise RuntimeError("LYCAN_API_KEY is required.")

    # Create options and set headers manually to avoid 'storage' attribute issues
    # in some versions of supabase-py ClientOptions constructor
    opts = ClientOptions()
    opts.headers.update({
        "x-agent-api-key": settings.lycan_api_key,
        "x-client-info": f"lycan-local-agent/{settings.agent_version}",
    })

    return create_client(
        settings.supabase_url,
        settings.supabase_anon_key,
        options=opts
    )


def resolve_user_id(client: Client, api_key: str) -> str:
    resp = (
        client.table("profiles")
        .select("id")
        .eq("api_key", api_key)
        .limit(1)
        .execute()
    )
    if not resp.data:
        raise RuntimeError("Unable to resolve user_id from LYCAN_API_KEY.")
    return resp.data[0]["id"]


def upsert_agent_state(client: Client, user_id: str, worker_id: str, version: str, status: str) -> None:
    payload = {
        "user_id": user_id,
        "worker_id": worker_id,
        "last_seen": now_iso(),
        "status": status,
        "version": version,
        "public_ip": get_public_ip(),
        "metadata": get_local_context(),
    }
    client.table("agents").upsert(payload, on_conflict="user_id,worker_id").execute()


def update_agent_error_status(
    client: Client,
    user_id: Optional[str],
    worker_id: str,
    version: str,
    error_message: str,
) -> None:
    if not user_id:
        logging.error("Cannot persist agent error state without user_id: %s", error_message)
        return
    upsert_agent_state(client, user_id, worker_id, version, f"Error: {error_message}")


def verify_environment(client: Client, settings: Settings, user_id: Optional[str]) -> str:
    if not shutil.which("nmap"):
        raise RuntimeError("Nmap no encontrado")

    try:
        with socket.create_connection(("8.8.8.8", 53), timeout=5):
            pass
    except Exception as exc:
        raise RuntimeError(f"Sin conectividad a 8.8.8.8 ({exc})") from exc

    try:
        verified_user_id = resolve_user_id(client, settings.lycan_api_key)
    except Exception as exc:
        raise RuntimeError(f"LYCAN_API_KEY inválida ({exc})") from exc

    if user_id and verified_user_id != user_id:
        raise RuntimeError("LYCAN_API_KEY no coincide con el usuario resuelto")

    return verified_user_id


def sign_results_payload(result: Dict[str, Any], signing_key: str) -> Dict[str, Any]:
    canonical_payload = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    signature = hmac.new(
        signing_key.encode("utf-8"),
        canonical_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    signed = dict(result)
    signed["meta"] = {
        "integrity": {
            "algo": "hmac-sha256",
            "signature": signature,
        },
        "signed_at": now_iso(),
    }
    return signed


SUPPORTED_MODULES = {
    "reconnaissance",
    "http_security",
    "port_scan",
    "sqli",
    "xss",
    "csrf",
    "idor",
    "ssrf",
    "file_upload",
    "xxe",
    "csp",
    "tls",
    "cookies",
    "api_security",
    "info_disclosure",
}


def finding(
    module: str,
    severity: str,
    title: str,
    description: str,
    remediation: Optional[str] = None,
    cwe: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "module": module,
        "severity": severity,
        "title": title,
        "description": description,
    }
    if remediation:
        row["remediation"] = remediation
    if cwe:
        row["cwe"] = cwe
    if metadata:
        row["metadata"] = metadata
    return row


def parse_target(target: str) -> Tuple[str, str]:
    raw = target.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        host = parsed.hostname or raw
        base = f"{parsed.scheme}://{host}"
    else:
        host = raw.split("/")[0]
        base = f"https://{host}"
    return host, base


def run_command(cmd: List[str], timeout_seconds: int) -> Tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def http_fetch(url: str, timeout_seconds: int) -> Tuple[int, Dict[str, str], str]:
    req = urllib.request.Request(url, headers={"User-Agent": "Lycan-Agent/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        body = resp.read(300_000).decode("utf-8", errors="replace")
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return int(resp.status), headers, body


def run_reconnaissance(target: str, settings: Settings) -> List[Dict[str, Any]]:
    host, _ = parse_target(target)
    findings: List[Dict[str, Any]] = []
    try:
        ip = socket.gethostbyname(host)
        findings.append(finding("reconnaissance", "info", "Host resolvable", f"{host} resolves to {ip}."))
    except Exception as exc:
        return [finding("reconnaissance", "high", "DNS resolution failed", str(exc), cwe="CWE-200")]

    if shutil.which("nslookup"):
        _, txt_out, _ = run_command(["nslookup", "-type=TXT", host], settings.request_timeout_seconds)
        txt_low = txt_out.lower()
        if "v=spf1" not in txt_low:
            findings.append(
                finding(
                    "reconnaissance",
                    "medium",
                    "Missing SPF record",
                    f"No SPF TXT record detected for {host}.",
                    "Add SPF TXT record to reduce spoofing risk.",
                    "CWE-290",
                )
            )
        _, dmarc_out, _ = run_command(["nslookup", "-type=TXT", f"_dmarc.{host}"], settings.request_timeout_seconds)
        if "v=dmarc1" not in dmarc_out.lower():
            findings.append(
                finding(
                    "reconnaissance",
                    "medium",
                    "Missing DMARC record",
                    f"No DMARC policy detected for {host}.",
                    "Publish a DMARC TXT policy.",
                    "CWE-290",
                )
            )
    return findings


def _build_evidence(status: int, headers: Dict[str, str], body: str) -> Dict[str, Any]:
    """Build an evidence object capturing the full HTTP response."""
    return {
        "http_status": status,
        "response_headers": dict(headers),
        "body_sample": body[:2000],
    }


def run_http_security(target: str, settings: Settings) -> List[Dict[str, Any]]:
    _, base = parse_target(target)
    findings: List[Dict[str, Any]] = []
    try:
        status, headers, body = http_fetch(base, settings.request_timeout_seconds)
    except Exception as exc:
        return [finding("http_security", "high", "HTTP fetch failed", str(exc), cwe="CWE-319")]

    evidence = _build_evidence(status, headers, body)

    required = {
        "strict-transport-security": ("high", "Missing HSTS", "CWE-319"),
        "content-security-policy": ("medium", "Missing CSP", "CWE-79"),
        "x-frame-options": ("medium", "Missing X-Frame-Options", "CWE-1021"),
        "x-content-type-options": ("low", "Missing X-Content-Type-Options", "CWE-116"),
        "referrer-policy": ("low", "Missing Referrer-Policy", "CWE-200"),
    }
    for header, (severity, title, cwe) in required.items():
        if header not in headers:
            f = finding(
                "http_security",
                severity,
                title,
                f"{header} header is not set.",
                f"Set {header} with a secure value.",
                cwe,
            )
            f["evidence"] = evidence
            findings.append(f)
    return findings


def run_port_scan(target: str, settings: Settings) -> List[Dict[str, Any]]:
    host, _ = parse_target(target)
    nmap_result = run_nmap(host, settings.nmap_timeout_seconds)
    return nmap_result["findings"]


def _run_sqlmap_confirmation(test_url: str, timeout_seconds: int) -> Dict[str, Any]:
    """
    Second sqlmap pass: extract banner + current DB to confirm exploitation.
    Returns a critical_evidence dict or empty dict on failure.
    """
    if not shutil.which("sqlmap"):
        return {}
    try:
        _, out, err = run_command(
            [
                "sqlmap",
                "-u", test_url,
                "--batch",
                "--banner",
                "--current-db",
                "--technique=BEUSTQ",
                "--risk=1",
                "--level=1",
                "--flush-session",   # discard cached data from previous scans
            ],
            min(timeout_seconds, 300),  # hard cap: never exceed 300 s
        )
        combined = f"{out}\n{err}"

        banner: Optional[str] = None
        current_db: Optional[str] = None

        for line in combined.splitlines():
            low = line.strip().lower()
            if "banner" in low and ":" in line:
                banner = line.split(":", 1)[-1].strip()
            if "current database" in low and ":" in line:
                current_db = line.split(":", 1)[-1].strip().strip("'")

        return {
            "sqlmap_banner": banner,
            "sqlmap_current_db": current_db,
            "sqlmap_raw_output": combined[:3000],
            "confirmed_at": now_iso(),
        }
    except Exception as exc:
        logging.warning("SQLi confirmation pass failed: %s", exc)
        return {}


def run_sqli(target: str, settings: Settings) -> List[Dict[str, Any]]:
    host, _ = parse_target(target)
    if shutil.which("sqlmap"):
        test_url = f"https://{host}/?id=1"
        # Capture HTTP evidence before running sqlmap
        evidence: Optional[Dict[str, Any]] = None
        try:
            st, hdrs, bdy = http_fetch(test_url, settings.request_timeout_seconds)
            evidence = _build_evidence(st, hdrs, bdy)
        except Exception:
            pass

        rc, out, err = run_command(
            ["sqlmap", "-u", test_url, "--batch", "--risk=1", "--level=1", "--crawl=1", "--smart"],
            max(settings.request_timeout_seconds * 4, 30),
        )
        combined = f"{out}\n{err}".lower()
        if "is vulnerable" in combined or "sql injection" in combined:
            f = finding(
                "sqli",
                "critical",
                "Potential SQL injection",
                f"sqlmap indicated injectable behavior on {test_url}.",
                "Use parameterized queries and strict input validation.",
                "CWE-89",
            )
            if evidence:
                f["evidence"] = evidence

            # Confirmation pass: extract banner + current DB (max 300 s)
            confirm_timeout = min(max(settings.request_timeout_seconds * 6, 60), 300)
            critical_evidence = _run_sqlmap_confirmation(test_url, confirm_timeout)
            if critical_evidence:
                f["critical_evidence"] = critical_evidence
                logging.info(
                    "SQLi confirmed — DB: %s | Banner: %s",
                    critical_evidence.get("sqlmap_current_db"),
                    critical_evidence.get("sqlmap_banner"),
                )

            return [f]
        if rc != 0:
            return [finding("sqli", "info", "sqlmap inconclusive", "No conclusive SQLi finding from sqlmap run.")]
    return [finding("sqli", "info", "No obvious SQLi", "No obvious SQL injection vectors identified.")]



def run_xss(target: str, settings: Settings) -> List[Dict[str, Any]]:
    host, _ = parse_target(target)
    payload = "<script>alert(1)</script>"
    url = f"https://{host}/search?q={quote(payload)}"
    try:
        status, headers, body = http_fetch(url, settings.request_timeout_seconds)
        if payload.lower() in body.lower():
            f = finding(
                "xss",
                "high",
                "Potential reflected XSS",
                "Input appears reflected without sanitization.",
                "Escape untrusted output and enforce CSP.",
                "CWE-79",
            )
            f["evidence"] = _build_evidence(status, headers, body)
            return [f]
    except Exception:
        pass
    return [finding("xss", "info", "No obvious XSS", "No obvious reflected XSS detected.")]


def run_csrf(target: str, settings: Settings) -> List[Dict[str, Any]]:
    _, base = parse_target(target)
    try:
        _, headers, _ = http_fetch(base, settings.request_timeout_seconds)
    except Exception as exc:
        return [finding("csrf", "info", "CSRF check skipped", str(exc))]
    cookies = headers.get("set-cookie", "")
    if cookies and "samesite" not in cookies.lower():
        return [finding("csrf", "medium", "Missing SameSite on cookies", "Session cookie lacks SameSite attribute.", cwe="CWE-352")]
    return [finding("csrf", "info", "No obvious CSRF weakness", "No obvious CSRF signal detected.")]


def run_idor(target: str, settings: Settings) -> List[Dict[str, Any]]:
    host, _ = parse_target(target)
    urls = [f"https://{host}/api/users/1", f"https://{host}/api/users/2"]
    statuses: List[int] = []
    for url in urls:
        try:
            status, _, _ = http_fetch(url, settings.request_timeout_seconds)
            statuses.append(status)
        except Exception:
            continue
    if len(statuses) == 2 and all(s < 400 for s in statuses):
        return [finding("idor", "medium", "Potential IDOR exposure", "Sequential IDs returned successful responses.", cwe="CWE-639")]
    return [finding("idor", "info", "No obvious IDOR", "No obvious insecure direct object reference pattern found.")]


def run_ssrf(target: str, settings: Settings) -> List[Dict[str, Any]]:
    host, _ = parse_target(target)
    probe = quote("http://169.254.169.254/latest/meta-data/")
    url = f"https://{host}/fetch?url={probe}"
    try:
        _, _, body = http_fetch(url, settings.request_timeout_seconds)
        if "meta-data" in body.lower() or "iam/" in body.lower():
            return [finding("ssrf", "critical", "Potential SSRF", "Metadata-like response observed via URL fetch endpoint.", cwe="CWE-918")]
    except Exception:
        pass
    return [finding("ssrf", "info", "No obvious SSRF", "No obvious SSRF behavior detected.")]


def run_file_upload(target: str, settings: Settings) -> List[Dict[str, Any]]:
    host, _ = parse_target(target)
    url = f"https://{host}/upload"
    try:
        status, _, body = http_fetch(url, settings.request_timeout_seconds)
        if status < 400 and ("upload" in body.lower() or "multipart/form-data" in body.lower()):
            return [finding("file_upload", "medium", "Upload surface detected", "Upload endpoint appears reachable; verify strict validation.", cwe="CWE-434")]
    except Exception:
        pass
    return [finding("file_upload", "info", "No obvious upload risk", "No obvious file upload endpoint identified.")]


def run_xxe(target: str, settings: Settings) -> List[Dict[str, Any]]:
    _, base = parse_target(target)
    try:
        _, headers, _ = http_fetch(base, settings.request_timeout_seconds)
        if "application/xml" in (headers.get("content-type", "").lower()):
            return [finding("xxe", "medium", "XML processing surface detected", "XML content type observed; ensure external entities are disabled.", cwe="CWE-611")]
    except Exception:
        pass
    return [finding("xxe", "info", "No obvious XXE surface", "No obvious XML parser exposure detected.")]


def run_csp(target: str, settings: Settings) -> List[Dict[str, Any]]:
    _, base = parse_target(target)
    try:
        _, headers, _ = http_fetch(base, settings.request_timeout_seconds)
    except Exception as exc:
        return [finding("csp", "info", "CSP check skipped", str(exc))]
    csp = headers.get("content-security-policy", "")
    if not csp:
        return [finding("csp", "medium", "Missing CSP", "No Content-Security-Policy header found.", cwe="CWE-79")]
    if "unsafe-inline" in csp.lower():
        return [finding("csp", "medium", "Weak CSP policy", "CSP allows unsafe-inline scripts.", cwe="CWE-79")]
    return [finding("csp", "info", "CSP present", "Content-Security-Policy header detected.")]


def run_tls(target: str, settings: Settings) -> List[Dict[str, Any]]:
    host, _ = parse_target(target)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=settings.request_timeout_seconds) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version() or "unknown"
                findings: List[Dict[str, Any]] = [finding("tls", "info", "TLS reachable", f"Negotiated protocol: {version}.")]
                if version in {"TLSv1", "TLSv1.1"}:
                    findings.append(finding("tls", "high", "Legacy TLS version", f"Server negotiated {version}.", "Disable TLSv1.0/TLSv1.1.", "CWE-326"))
                return findings
    except Exception as exc:
        return [finding("tls", "high", "TLS handshake failed", str(exc), cwe="CWE-295")]


def run_cookies(target: str, settings: Settings) -> List[Dict[str, Any]]:
    _, base = parse_target(target)
    try:
        _, headers, _ = http_fetch(base, settings.request_timeout_seconds)
    except Exception as exc:
        return [finding("cookies", "info", "Cookie check skipped", str(exc))]
    cookie = headers.get("set-cookie", "")
    findings: List[Dict[str, Any]] = []
    if cookie:
        low = cookie.lower()
        if "secure" not in low:
            findings.append(finding("cookies", "medium", "Cookie missing Secure", "Session cookie may be sent over HTTP.", cwe="CWE-614"))
        if "httponly" not in low:
            findings.append(finding("cookies", "medium", "Cookie missing HttpOnly", "Cookie accessible from JavaScript.", cwe="CWE-1004"))
        if "samesite" not in low:
            findings.append(finding("cookies", "low", "Cookie missing SameSite", "CSRF exposure may increase.", cwe="CWE-352"))
    if not findings:
        findings.append(finding("cookies", "info", "No obvious cookie issues", "No obvious cookie misconfiguration detected."))
    return findings


def run_api_security(target: str, settings: Settings) -> List[Dict[str, Any]]:
    host, _ = parse_target(target)
    url = f"https://{host}/api"
    try:
        _, headers, _ = http_fetch(url, settings.request_timeout_seconds)
    except Exception as exc:
        return [finding("api_security", "info", "API check skipped", str(exc))]
    findings: List[Dict[str, Any]] = []
    origin = headers.get("access-control-allow-origin", "")
    if origin.strip() == "*":
        findings.append(finding("api_security", "medium", "Permissive CORS", "API allows all origins.", cwe="CWE-942"))
    if "x-ratelimit-limit" not in headers and "ratelimit-limit" not in headers:
        findings.append(finding("api_security", "low", "No rate-limit header", "No explicit rate-limiting signal in API response."))
    if not findings:
        findings.append(finding("api_security", "info", "No obvious API security issue", "No obvious API security weakness detected."))
    return findings


def run_info_disclosure(target: str, settings: Settings) -> List[Dict[str, Any]]:
    _, base = parse_target(target)
    try:
        _, headers, body = http_fetch(base, settings.request_timeout_seconds)
    except Exception as exc:
        return [finding("info_disclosure", "info", "Info disclosure check skipped", str(exc))]
    findings: List[Dict[str, Any]] = []
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server and re.search(r"\d", server):
        findings.append(finding("info_disclosure", "low", "Server version disclosure", f"Server header reveals version: {server}", cwe="CWE-200"))
    if powered:
        findings.append(finding("info_disclosure", "low", "X-Powered-By exposed", f"Header reveals framework: {powered}", cwe="CWE-200"))
    lower_body = body.lower()
    if any(tok in lower_body for tok in ["exception", "stack trace", "sql syntax", "traceback"]):
        findings.append(finding("info_disclosure", "medium", "Verbose error disclosure", "Response appears to expose internal error details.", cwe="CWE-209"))
    if not findings:
        findings.append(finding("info_disclosure", "info", "No obvious information disclosure", "No obvious disclosure patterns found."))
    return findings


def run_module(module_id: str, target: str, settings: Settings) -> List[Dict[str, Any]]:
    dispatch = {
        "reconnaissance": run_reconnaissance,
        "http_security": run_http_security,
        "port_scan": run_port_scan,
        "sqli": run_sqli,
        "xss": run_xss,
        "csrf": run_csrf,
        "idor": run_idor,
        "ssrf": run_ssrf,
        "file_upload": run_file_upload,
        "xxe": run_xxe,
        "csp": run_csp,
        "tls": run_tls,
        "cookies": run_cookies,
        "api_security": run_api_security,
        "info_disclosure": run_info_disclosure,
    }
    fn = dispatch.get(module_id)
    if not fn:
        return [finding(module_id, "info", "Unknown module", f"Module '{module_id}' is not supported by this agent build.")]
    return fn(target, settings)


def normalize_modules(raw_modules: Any) -> List[str]:
    if not isinstance(raw_modules, list):
        return ["reconnaissance", "http_security", "port_scan"]
    normalized: List[str] = []
    for item in raw_modules:
        module_id = str(item).strip()
        if module_id in SUPPORTED_MODULES:
            normalized.append(module_id)
    return normalized or ["reconnaissance", "http_security", "port_scan"]


def calculate_score(findings: List[Dict[str, Any]]) -> int:
    penalties = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}
    by_severity: Dict[str, int] = {}
    for row in findings:
        sev = str(row.get("severity", "info"))
        by_severity[sev] = by_severity.get(sev, 0) + 1
    total = 0.0
    for sev, count in by_severity.items():
        base = penalties.get(sev, 0)
        if base == 0 or count == 0:
            continue
        total += base * (1 + (count.bit_length() - 1) * 0.5)
    total = min(total, 95)
    return max(5, round(100 - total))


def send_heartbeat(
    client: Client,
    user_id: str,
    worker_id: str,
    version: str,
    stop_event: threading.Event,
    interval_seconds: int,
) -> None:
    while not stop_event.is_set():
        try:
            upsert_agent_state(client, user_id, worker_id, version, "online")
            logging.info("Heartbeat sent | worker_id=%s", worker_id)
            _agent_console.log_heartbeat(worker_id)
        except Exception as exc:
            logging.exception("Heartbeat error: %s", exc)
            _agent_console.log_error(f"Heartbeat error: {exc}")

        stop_event.wait(interval_seconds)


def claim_pending_job(client: Client, user_id: str, worker_id: str) -> Optional[Dict[str, Any]]:
    jobs_resp = (
        client.table("scan_jobs")
        .select("id, scan_id, user_id, domain_id, status, modules")
        .eq("status", "pending")
        .eq("user_id", user_id)
        .order("created_at", desc=False)
        .limit(1)
        .execute()
    )
    if not jobs_resp.data:
        return None

    job = jobs_resp.data[0]
    claim_resp = (
        client.table("scan_jobs")
        .update(
            {
                "status": "processing",
                "worker_id": worker_id,
            }
        )
        .eq("id", job["id"])
        .eq("status", "pending")
        .eq("user_id", user_id)
        .select("id, scan_id, user_id, domain_id, status, modules")
        .execute()
    )

    if not claim_resp.data:
        return None
    return claim_resp.data[0]


def get_target_for_scan(client: Client, job: Dict[str, Any]) -> str:
    scan_resp = (
        client.table("scans")
        .select("id, target_url")
        .eq("id", job["scan_id"])
        .single()
        .execute()
    )
    scan_row = scan_resp.data or {}
    target = (scan_row.get("target_url") or "").strip()
    if target:
        return target

    if job.get("domain_id"):
        domain_resp = (
            client.table("domains")
            .select("hostname")
            .eq("id", job["domain_id"])
            .single()
            .execute()
        )
        domain_row = domain_resp.data or {}
        domain_target = (domain_row.get("hostname") or "").strip()
        if domain_target:
            return domain_target

    raise RuntimeError(f"No target could be resolved for scan {job['scan_id']}.")


def run_nmap(target: str, timeout_seconds: int) -> Dict[str, Any]:
    cmd = ["nmap", "-sV", "-T4"]
    if is_in_local_subnet(target):
        cmd.extend(["-Pn", "--min-parallelism", "10"])
    cmd.append(target)
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )

    result = {
        "target": target,
        "command": " ".join(cmd),
        "return_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "findings": parse_nmap_output(proc.stdout),
        "finished_at": now_iso(),
    }
    if proc.returncode != 0:
        raise RuntimeError(f"Nmap failed rc={proc.returncode}: {proc.stderr.strip()[:400]}")
    return result


def parse_nmap_output(output: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    pattern = re.compile(r"^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(.+)$")

    for line in output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue

        port, protocol, state, service = match.groups()
        findings.append(
            {
                "module": "nmap_service_scan",
                "severity": "info",
                "title": f"Port {port}/{protocol} {state}",
                "description": f"Service fingerprint: {service}",
                "metadata": {
                    "port": int(port),
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                },
            }
        )

    return findings


def mark_scan_running(client: Client, scan_id: str) -> None:
    client.table("scans").update({"status": "running", "started_at": now_iso()}).eq("id", scan_id).execute()


def mark_success(client: Client, job_id: str, scan_id: str, result: Dict[str, Any]) -> None:
    client.table("scans").update(
        {
            "status": "completed",
            "results": result,
            "completed_at": now_iso(),
        }
    ).eq("id", scan_id).execute()

    client.table("scan_jobs").update(
        {
            "status": "done",
            "completed_at": now_iso(),
        }
    ).eq("id", job_id).execute()


def mark_failure(client: Client, job_id: str, scan_id: str, error_message: str) -> None:
    safe_message = error_message[:1500]
    client.table("scans").update(
        {
            "status": "failed",
            "error_message": safe_message,
            "results": {"error": safe_message, "failed_at": now_iso()},
            "completed_at": now_iso(),
        }
    ).eq("id", scan_id).execute()

    client.table("scan_jobs").update(
        {
            "status": "failed",
            "error": safe_message,
            "completed_at": now_iso(),
        }
    ).eq("id", job_id).execute()


def report_progress(
    client: Client,
    job_id: str,
    module_name: str,
    pct: int,
) -> None:
    """
    Write current progress to scan_jobs.progress_message.
    Fire-and-forget: never raises so it cannot abort a scan.
    """
    try:
        client.table("scan_jobs").update(
            {
                "progress_message": f"[{pct}%] Running: {module_name}",
                "progress_pct": pct,
            }
        ).eq("id", job_id).execute()
    except Exception as exc:
        logging.warning("report_progress failed (non-fatal): %s", exc)


def process_job(client: Client, settings: Settings, job: Dict[str, Any]) -> None:
    job_id = str(job["id"])
    scan_id = str(job["scan_id"])
    logging.info("Processing job=%s scan=%s", job_id, scan_id)

    try:
        mark_scan_running(client, scan_id)
        target = get_target_for_scan(client, job)
        modules = normalize_modules(job.get("modules"))
        total_modules = len(modules)
        all_findings: List[Dict[str, Any]] = []
        module_details: Dict[str, Any] = {}

        for idx, module_id in enumerate(modules):
            # Report progress BEFORE running the module (0-95% range)
            pct = round((idx / total_modules) * 95) if total_modules > 0 else 0
            report_progress(client, job_id, module_id, pct)
            _agent_console.log_module_start(module_id, target, pct)

            try:
                module_findings = run_module(module_id, target, settings)
                all_findings.extend(module_findings)
                module_details[module_id] = {
                    "status": "completed",
                    "findings_count": len(module_findings),
                }

                # ── Console: print each actionable finding immediately ──────
                for f in module_findings:
                    sev = f.get("severity", "info")
                    if sev in ("critical", "high", "medium"):
                        _agent_console.log_vuln(
                            module_id,
                            sev,
                            f.get("title", "Unknown"),
                            target,
                        )
                    if f.get("critical_evidence"):
                        _agent_console.log_critical_evidence(f["critical_evidence"])

            except Exception as module_exc:
                logging.exception("Module %s failed: %s", module_id, module_exc)
                _agent_console.log_error(f"Module {module_id} failed: {module_exc}")
                module_details[module_id] = {
                    "status": "failed",
                    "error": str(module_exc)[:400],
                    "findings_count": 0,
                }

        # Final progress tick before signing
        report_progress(client, job_id, "finalizing", 98)

        result = {
            "target": target,
            "modules_requested": modules,
            "modules_completed": [m for m in modules if module_details.get(m, {}).get("status") == "completed"],
            "module_details": module_details,
            "findings": all_findings,
            "score": calculate_score(all_findings),
            "finished_at": now_iso(),
        }
        # sign_results_payload covers ALL fields including critical_evidence in findings
        signed_result = sign_results_payload(result, settings.lycan_api_key)
        mark_success(client, job_id, scan_id, signed_result)
        logging.info("Completed job=%s scan=%s target=%s", job_id, scan_id, target)
        _agent_console.log_scan_complete(
            job_id, target, result["score"], len(all_findings)
        )
    except Exception as exc:
        logging.exception("Job failed job=%s scan=%s: %s", job_id, scan_id, exc)
        _agent_console.log_error(f"Job {job_id} failed: {exc}")
        try:
            mark_failure(client, job_id, scan_id, str(exc))
        except Exception as nested:
            logging.exception(
                "CRITICAL: failed to persist failure state for job=%s scan=%s: %s",
                job_id,
                scan_id,
                nested,
            )


def _dispatch_job_safe(
    client: Client,
    settings: Settings,
    user_id: str,
    executor: ThreadPoolExecutor,
) -> None:
    """Claim the oldest pending job and dispatch it to the thread pool."""
    try:
        job = claim_pending_job(client, user_id, settings.worker_id)
        if job:
            logging.info("Realtime trigger: dispatching job=%s", job.get("id"))
            executor.submit(process_job, client, settings, job)
        else:
            logging.debug("Realtime event received but no claimable job found.")
    except Exception as exc:
        logging.exception("Error during realtime job dispatch: %s", exc)


def start_realtime_listener(
    client: Client,
    settings: Settings,
    user_id: str,
    stop_event: threading.Event,
    executor: ThreadPoolExecutor,
) -> None:
    """
    Subscribe to Supabase Realtime for INSERT events on scan_jobs
    filtered by the current user's user_id and status='pending'.
    Runs in its own daemon thread.
    """
    channel_name = f"agent-jobs-{user_id[:8]}"

    def _on_insert(payload: Dict[str, Any]) -> None:
        record = payload.get("record") or payload.get("new") or {}
        if str(record.get("user_id", "")) == user_id and record.get("status") == "pending":
            logging.info("Realtime INSERT received for scan_job=%s", record.get("id"))
            _dispatch_job_safe(client, settings, user_id, executor)

    try:
        channel = (
            client.channel(channel_name)
            .on_postgres_changes(
                event="INSERT",
                schema="public",
                table="scan_jobs",
                filter=f"user_id=eq.{user_id}",
                callback=_on_insert,
            )
            .subscribe()
        )
        logging.info("Realtime subscription active on channel '%s'", channel_name)

        # Keep the subscription alive until stop_event is set
        while not stop_event.is_set():
            stop_event.wait(timeout=5)

        # Graceful unsubscribe
        try:
            client.remove_channel(channel)
            logging.info("Realtime channel '%s' removed.", channel_name)
        except Exception as exc:
            logging.warning("Error removing realtime channel: %s", exc)

    except Exception as exc:
        logging.exception("Realtime listener failed: %s", exc)
        # Signal the main thread to shut down if realtime is unrecoverable
        stop_event.set()


def run(cli_args: Optional[argparse.Namespace] = None) -> None:
    load_dotenv()
    load_config()  # inject ~/.lycan/config.json into os.environ (lowest priority)

    # Check for updates silently on startup
    check_for_updates(silent=True)

    # CLI flags override everything else
    if cli_args is not None:
        if getattr(cli_args, "key", None):
            os.environ["LYCAN_API_KEY"] = cli_args.key
        if getattr(cli_args, "name", None):
            os.environ["WORKER_ID"] = cli_args.name
        if getattr(cli_args, "verbose", False):
            os.environ["AGENT_MODE"] = "VERBOSE"

    # Bootstrap settings first so we can read agent_mode for logging level
    try:
        settings = Settings()
    except ValidationError as exc:
        logging.error("Invalid agent configuration: %s", exc)
        raise SystemExit(1) from exc

    if not settings.lycan_api_key:
        print("Error: Use 'lycan setup' to configure your API Key", file=sys.stderr)
        raise SystemExit(1)

    setup_logging(settings.agent_mode)

    # Replace module-level console with the correct mode instance
    global _agent_console
    _agent_console = AgentConsole(mode=settings.agent_mode)
    _agent_console.display_banner(settings.agent_version, settings.worker_id)

    stop_event = threading.Event()

    user_id: Optional[str] = None
    try:
        client = build_client(settings)
        user_id = resolve_user_id(client, settings.lycan_api_key)
    except Exception as exc:
        logging.error("Failed to initialize Supabase context: %s", exc)
        raise SystemExit(1) from exc

    logging.info("Starting Lycan local agent | worker_id=%s", settings.worker_id)

    try:
        user_id = verify_environment(client, settings, user_id)
        logging.info("Environment self-test passed.")
    except Exception as exc:
        error_text = str(exc)
        logging.error("Environment self-test failed: %s", error_text)
        try:
            update_agent_error_status(
                client,
                user_id,
                settings.worker_id,
                settings.agent_version,
                error_text,
            )
        except Exception as nested:
            logging.error("Failed to persist self-test failure state: %s", nested)
        raise SystemExit(1) from exc

    try:
        upsert_agent_state(client, user_id, settings.worker_id, settings.agent_version, "online")
    except Exception as exc:
        logging.warning("Initial online state update failed: %s", exc)

    def _handle_signal(signum: int, _frame: Any) -> None:
        logging.info("Signal %s received. Shutting down agent...", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # Thread pool for concurrent job execution (max 4 parallel scans)
    executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="scan-worker")

    # Heartbeat thread — completely independent from Realtime
    heartbeat_thread = threading.Thread(
        target=send_heartbeat,
        args=(
            client,
            user_id,
            settings.worker_id,
            settings.agent_version,
            stop_event,
            settings.heartbeat_interval_seconds,
        ),
        daemon=True,
        name="heartbeat-thread",
    )
    heartbeat_thread.start()

    # Realtime listener thread — replaces the polling while loop
    realtime_thread = threading.Thread(
        target=start_realtime_listener,
        args=(client, settings, user_id, stop_event, executor),
        daemon=True,
        name="realtime-thread",
    )
    realtime_thread.start()

    # Drain any jobs that arrived before the agent started (startup catch-up)
    _dispatch_job_safe(client, settings, user_id, executor)

    try:
        # Main thread only waits for shutdown signal
        stop_event.wait()
    finally:
        stop_event.set()
        executor.shutdown(wait=True, cancel_futures=False)
        heartbeat_thread.join(timeout=5)
        realtime_thread.join(timeout=5)
        try:
            upsert_agent_state(client, user_id, settings.worker_id, settings.agent_version, "offline")
            logging.info("Agent marked offline.")
        except Exception as exc:
            logging.warning("Failed to mark agent offline: %s", exc)


# ─── CLI: argparse + subcommands ───────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lycan",
        description="Lycan Security — Local Scan Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  lycan --setup                      # configure API Key\n"
            "  lycan start                        # start with config file / env vars\n"
            "  lycan start --key <API_KEY>        # override API key\n"
            "  lycan start --name my-node --verbose\n"
            "  lycan install-deps                 # install nmap + sqlmap\n"
            "  lycan update                       # update agent via Hot-Reload\n"
            "  lycan config                       # show active configuration\n"
        ),
    )
    
    parser.add_argument("--setup", action="store_true", help="Run interactive configuration setup")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # —— setup ——————————————————————————————————————————————
    sub.add_parser("setup", help="Interactive configuration setup")

    # —— update —————————————————————————————————————————————
    sub.add_parser("update", help="Actualiza el agente a la última versión (Hot-Reload)")

    # —— start ——————————————————————————————————————————————
    start_p = sub.add_parser("start", help="Start the scan agent")
    start_p.add_argument(
        "--key",
        metavar="API_KEY",
        help="Lycan API key (overrides LYCAN_API_KEY env var and config file)",
    )
    start_p.add_argument(
        "--name",
        metavar="WORKER_NAME",
        help="Custom worker/node name (overrides WORKER_ID)",
    )
    start_p.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Force VERBOSE console output regardless of AGENT_MODE",
    )

    # —— install-deps ————————————————————————————————————————
    sub.add_parser(
        "install-deps",
        help="Install system dependencies (nmap, sqlmap) via apt",
    )

    # —— config ——————————————————————————————————————————————
    sub.add_parser(
        "config",
        help="Display the active agent configuration (masks secrets)",
    )

    return parser


def cmd_setup() -> None:
    """Interactive setup to configure ~/.lycan/config.json."""
    print("[*] Lycan Security Agent Setup")
    
    try:
        api_key = input("Enter your Lycan API Key: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Setup cancelled.")
        raise SystemExit(1)

    if not api_key:
        print("[!] API Key is required.")
        raise SystemExit(1)

    cfg = load_config()
    cfg["lycan_api_key"] = api_key
    save_config(cfg)
    print(f"[\u2713] Configuration saved to {_CONFIG_PATH}")


def cmd_install_deps() -> None:
    """Install nmap + sqlmap using apt-get (requires root)."""
    packages = ["nmap", "sqlmap", "curl", "iputils-ping"]
    apt = shutil.which("apt-get") or shutil.which("apt")
    if not apt:
        print("[!] apt not found. Install nmap and sqlmap manually.", file=sys.stderr)
        raise SystemExit(1)
    print(f"[*] Installing: {', '.join(packages)}")
    cmd = [apt, "install", "-y", "--no-install-recommends"] + packages
    rc = subprocess.run(cmd, check=False).returncode
    if rc == 0:
        print("[\u2713] System dependencies installed.")
    else:
        print(f"[\u2717] apt returned exit code {rc}.", file=sys.stderr)
        raise SystemExit(rc)


def cmd_config() -> None:
    """Print the merged configuration (env > config file > defaults), masking secrets."""
    load_dotenv()
    load_config()

    try:
        settings = Settings()
    except Exception as e:
        print(f"[ERROR] Could not load settings: {e}")
        return

    def mask(val: str) -> str:
        return (val[:4] + "*" * (len(val) - 4)) if len(val) > 8 else "****"

    rows = {
        "API Key":      mask(settings.lycan_api_key) if settings.lycan_api_key else "(not set)",
        "Supabase URL": settings.supabase_url or "(not set)",
        "Worker ID":    settings.worker_id,
        "Agent Mode":   settings.agent_mode,
        "Heartbeat":    f"{settings.heartbeat_interval_seconds}s",
        "Version":      settings.agent_version,
        "Config file":  str(_CONFIG_PATH) + (" \u2713" if _CONFIG_PATH.exists() else " (missing)"),
    }

    con = Console()
    tbl = Table(
        title="[bold cyan]Lycan Agent \u2014 Active Configuration[/bold cyan]",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold white",
    )
    tbl.add_column("Setting", style="cyan", no_wrap=True)
    tbl.add_column("Value", style="white")
    for k, v in rows.items():
        tbl.add_row(k, str(v))
    con.print(tbl)


def main() -> None:
    """
    Entry point registered by setup.py as the 'lycan' console_script.
    Dispatches subcommands: start | install-deps | config | setup | update
    """
    parser = build_arg_parser()
    args = parser.parse_args()

    if getattr(args, "setup", False) or args.command == "setup":
        cmd_setup()
    elif args.command == "update":
        exec_update()
    elif args.command == "start":
        run(cli_args=args)
    elif args.command == "install-deps":
        cmd_install_deps()
    elif args.command == "config":
        cmd_config()
    else:
        # No subcommand given — print help
        parser.print_help()
        raise SystemExit(0)


if __name__ == "__main__":
    main()
