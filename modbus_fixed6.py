import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import struct, json, csv, time, socket, threading, os, sqlite3, html, queue, smtplib, math
from email.mime.text import MIMEText
from datetime import datetime
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, List

try:
    from pymodbus.client import ModbusTcpClient, ModbusSerialClient
    HAS_PYM = True
except ImportError:
    HAS_PYM = False
try:
    import openpyxl; HAS_XL = True
except ImportError:
    HAS_XL = False
try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
try:
    import paho.mqtt.client as mqtt_client
    HAS_MQTT = True
    _MQTT_V2 = hasattr(mqtt_client, "CallbackAPIVersion")
except ImportError:
    HAS_MQTT = False
    _MQTT_V2 = False
try:
    from pycomm3 import LogixDriver, SLCDriver
    HAS_PYCOMM3 = True
except ImportError:
    HAS_PYCOMM3 = False
try:
    import snap7
    HAS_SNAP7 = True
except ImportError:
    HAS_SNAP7 = False

FORMATS = ["Binary","Hex","UInt16","Int16","UInt32","Int32","Float32","UInt64","Int64","Float64","ASCII"]
BYTE_ORDERS = ["ABCD","BADC","CDAB","DCBA","ABCDEFGH","HGFEDCBA","GHEFCDAB","BADCFEHG"]
FC_LIST = ["Holding Registers","Input Registers","Coils","Discrete Inputs"]
WRITABLE = {"Coils","Holding Registers"}
PRESETS = [0, 1, 100, 255, 1000, 32767, 65535]
ZERO_PROTOCOLS = ["Modbus TCP","Rockwell EtherNet/IP","Unitronics PCOM","Siemens S7"]

FC_NAMES = {
    "read_coils": (1, "Read Coils"), "read_discrete_inputs": (2, "Read Discrete Inputs"),
    "read_holding_registers": (3, "Read Holding Registers"), "read_input_registers": (4, "Read Input Registers"),
    "write_coil": (5, "Write Single Coil"), "write_register": (6, "Write Single Register"),
    "write_coils": (15, "Write Multiple Coils"), "write_registers": (16, "Write Multiple Registers"),
}

EXCEPTION_CODES = {
    1: "Illegal Function", 2: "Illegal Data Address", 3: "Illegal Data Value",
    4: "Slave Device Failure", 5: "Acknowledge", 6: "Slave Device Busy",
    8: "Memory Parity Error", 10: "Gateway Path Unavailable",
    11: "Gateway Target Device Failed to Respond",
}

REGISTER_PRESETS = {
    "Temperature Setpoint": "Target temperature", "Current Temperature": "Measured temperature",
    "Pressure": "Line pressure", "Tank Level": "Liquid level", "Motor Speed": "Motor RPM",
    "Pump Status": "0=off, 1=on", "Valve Status": "0=closed, 1=open",
    "Auto Mode": "0=manual, 1=auto", "General Alarm": "0=healthy, 1=alarm",
    "Motor Current": "Motor current", "Voltage": "Line voltage", "Frequency": "Drive frequency",
    "Production Counter": "Production counter", "Weight": "Weight", "Flow Rate": "Flow rate",
    "pH": "Acidity", "Humidity": "Humidity", "Position": "Position", "Torque": "Torque",
    "Error Code": "Error code",
}
THEMES = {
    "dark": {"bg":"#1e1e2e","fg":"#ddd","entry":"#2a2a3a","tree":"#252535",
             "accent":"#0078d4","sel":"#0078d4","log_bg":"#0c0f12","log_fg":"#c9ffd1"},
    "light": {"bg":"#f5f5f7","fg":"#222","entry":"#ffffff","tree":"#ffffff",
              "accent":"#0078d4","sel":"#b3d9ff","log_bg":"#fafafa","log_fg":"#222"},
    "industrial": {"bg":"#2b2b2b","fg":"#e0e0e0","entry":"#1a1a1a","tree":"#1f1f1f",
                   "accent":"#ff9900","sel":"#ff9900","log_bg":"#0a0a0a","log_fg":"#00ff88"},
}

def regs_to_bytes(regs, order):
    n = len(regs)
    if n == 1: return struct.pack(">H", regs[0])
    if order in ("ABCD", "ABCDEFGH"): return struct.pack(">" + "H"*n, *regs)
    if order in ("BADC", "BADCFEHG"): return struct.pack("<" + "H"*n, *regs)
    if order in ("CDAB", "GHEFCDAB"):
        sw = [regs[1], regs[0]] if n == 2 else list(reversed(regs))
        return struct.pack(">" + "H"*n, *sw)
    if order in ("DCBA", "HGFEDCBA"): return struct.pack("<" + "H"*n, *reversed(regs))
    return struct.pack(">" + "H"*n, *regs)

def _registers_from_big_endian(b, order):
    n = len(b) // 2
    if n == 1:
        return list(struct.unpack(">H", b))
    if order in ("ABCD", "ABCDEFGH"):
        return list(struct.unpack(">" + "H"*n, b))
    if order in ("BADC", "BADCFEHG"):
        return list(struct.unpack("<" + "H"*n, b))
    if order in ("CDAB", "GHEFCDAB"):
        return list(reversed(struct.unpack(">" + "H"*n, b)))
    if order in ("DCBA", "HGFEDCBA"):
        return list(reversed(struct.unpack("<" + "H"*n, b)))
    return list(struct.unpack(">" + "H"*n, b))

def decode_value(regs, fmt, order="ABCD"):
    try:
        if fmt == "Hex": return " ".join(f"0x{r:04X}" for r in regs)
        if fmt == "Binary": return " ".join(f"{r:016b}" for r in regs)
        if fmt == "ASCII": return regs_to_bytes(regs, order).decode("ascii", errors="replace").rstrip("\x00")
        if fmt == "UInt16": return regs[0]
        if fmt == "Int16": return regs[0] if regs[0] < 32768 else regs[0] - 65536
        if fmt == "UInt32": return struct.unpack(">I", regs_to_bytes(regs[:2], order))[0]
        if fmt == "Int32": return struct.unpack(">i", regs_to_bytes(regs[:2], order))[0]
        if fmt == "Float32":
            v = struct.unpack(">f", regs_to_bytes(regs[:2], order))[0]
            return v if math.isfinite(v) else None
        if fmt == "UInt64": return struct.unpack(">Q", regs_to_bytes(regs[:4], order))[0]
        if fmt == "Int64": return struct.unpack(">q", regs_to_bytes(regs[:4], order))[0]
        if fmt == "Float64":
            v = struct.unpack(">d", regs_to_bytes(regs[:4], order))[0]
            return v if math.isfinite(v) else None
    except Exception as e:
        return f"ERR({e})"
    return regs[0] if regs else 0

def encode_value(value, fmt, order="ABCD"):
    if fmt in ("UInt16","Int16"):
        return [int(float(value)) & 0xFFFF]
    if fmt == "Hex":
        v = int(value, 16) if isinstance(value, str) else int(value)
        return [v & 0xFFFF]
    if fmt == "Binary":
        v = int(value, 2) if isinstance(value, str) else int(value)
        return [v & 0xFFFF]
    if fmt == "UInt32":
        b = struct.pack(">I", int(float(value)) & 0xFFFFFFFF)
    elif fmt == "Int32":
        b = struct.pack(">i", int(float(value)))
    elif fmt == "Float32":
        b = struct.pack(">f", float(value))
    elif fmt == "UInt64":
        b = struct.pack(">Q", int(float(value)) & 0xFFFFFFFFFFFFFFFF)
    elif fmt == "Int64":
        b = struct.pack(">q", int(float(value)))
    elif fmt == "Float64":
        b = struct.pack(">d", float(value))
    elif fmt == "ASCII":
        b = str(value).encode("ascii", errors="replace")[:8].ljust(8, b"\x00")
    else:
        return [int(float(value)) & 0xFFFF]
    return _registers_from_big_endian(b, order)

def reg_count(fmt):
    return {"Float64":4,"Int64":4,"UInt64":4,"Float32":2,"Int32":2,"UInt32":2,"ASCII":4}.get(fmt, 1)

def fmt_scale(val, scale):
    if isinstance(val, (int, float)) and scale and scale != 1.0:
        return round(val * scale, 6)
    return val

def fmt_unscale(val, scale):
    if isinstance(val, (int, float)) and scale and scale != 1.0 and scale != 0:
        return val / scale
    return val

def fmt_uptime(seconds):
    seconds = int(seconds); h, r = divmod(seconds, 3600); m, s = divmod(r, 60)
    if h: return f"{h}h {m}m"
    if m: return f"{m}m {s}s"
    return f"{s}s"

def explain_exception(result):
    if result is None:
        return "No response from device (timeout)."
    if not hasattr(result, "isError") or not result.isError():
        return None
    code = None
    for attr in ("exception_code", "exceptionCode"):
        if hasattr(result, attr):
            try:
                code = int(getattr(result, attr)); break
            except: pass
    if code is not None:
        return f"[Error {code}] {EXCEPTION_CODES.get(code, 'Unknown Modbus exception')}"
    s = str(result)
    for c in EXCEPTION_CODES:
        if f"={c})" in s or f"code={c}" in s or f"code {c}" in s:
            return f"[Error {c}] {EXCEPTION_CODES[c]}"
    return f"Device error: {s}"

class FormatDetector:
    @staticmethod
    def guess(raw_regs, previous_raw=None):
        if not raw_regs: return []
        results = []
        v0 = raw_regs[0]
        if v0 in (0, 1): results.append(("UInt16", "ABCD", 0.7, f"value={v0}"))
        else: results.append(("UInt16", "ABCD", 0.6, f"value={v0}"))
        signed = v0 if v0 < 32768 else v0 - 65536
        if -1000 < signed < 0: results.append(("Int16", "ABCD", 0.5, f"negative: {signed}"))
        if len(raw_regs) >= 2:
            for order in ("ABCD", "CDAB", "BADC", "DCBA"):
                try:
                    f32 = decode_value(raw_regs[:2], "Float32", order)
                    if isinstance(f32, float) and -1e10 < f32 < 1e10:
                        results.append(("Float32", order, 0.4, f"float={f32:.3f}"))
                except: pass
            for order in ("ABCD", "CDAB"):
                try:
                    i32 = decode_value(raw_regs[:2], "Int32", order)
                    if isinstance(i32, int) and abs(i32) < 1e9:
                        results.append(("Int32", order, 0.35, f"int32={i32}"))
                except: pass
        if len(raw_regs) >= 4:
            for order in ("ABCD", "CDAB"):
                try:
                    f64 = decode_value(raw_regs[:4], "Float64", order)
                    if isinstance(f64, float) and abs(f64) < 1e15:
                        results.append(("Float64", order, 0.3, f"double={f64:.3f}"))
                except: pass
        if len(raw_regs) >= 2:
            try:
                s = decode_value(raw_regs[:4] if len(raw_regs) >= 4 else raw_regs[:2], "ASCII", "ABCD")
                if s and all(32 <= ord(c) < 127 for c in s.strip()):
                    results.append(("ASCII", "ABCD", 0.5, f"ASCII='{s.strip()}'"))
            except: pass
        if previous_raw and previous_raw[0] != v0:
            results.append(("UInt16", "ABCD", 0.55, f"changing ({previous_raw[0]}\u2192{v0})"))
        seen = set(); unique = []
        for fmt, order, conf, reason in sorted(results, key=lambda x: -x[2]):
            key = (fmt, order)
            if key in seen: continue
            seen.add(key); unique.append((fmt, order, conf, reason))
        return unique[:5]

@dataclass(eq=False)
class WatchEntry:
    addr: int
    fc: str = "Holding Registers"
    fmt: str = "UInt16"
    order: str = "ABCD"
    name: str = ""
    scale: float = 1.0
    unit: str = ""
    slave_id: Optional[int] = None
    description: str = ""
    normal_min: Optional[float] = None
    normal_max: Optional[float] = None
    warn_min: Optional[float] = None
    warn_max: Optional[float] = None
    min_observed: Optional[float] = None
    max_observed: Optional[float] = None
    last_raw: Optional[List[int]] = None
    last_val: Optional[float] = None
    prev_val: Optional[float] = None
    last_read_at: Optional[float] = None
    last_change_at: Optional[float] = None
    trend: str = "\u2014"
    health: str = "\u2014"
    health_color: str = "#888"
    read_count: int = 0
    error_count: int = 0
    history: deque = field(default_factory=lambda: deque(maxlen=500))
    def __post_init__(self):
        if isinstance(self.addr, bool) or not isinstance(self.addr, int) or not 0 <= self.addr <= 65535:
            raise ValueError("Address must be 0..65535")
        if self.slave_id is not None:
            if isinstance(self.slave_id, bool) or not isinstance(self.slave_id, int) or not 0 <= self.slave_id <= 255:
                raise ValueError("Slave ID must be 0..255 or None")
        if self.fc not in FC_LIST: raise ValueError("Unsupported data area")
        if self.fmt not in FORMATS: raise ValueError("Unsupported format")
        if self.order not in BYTE_ORDERS: raise ValueError("Unsupported byte order")
        if not self.name: self.name = f"Reg_{self.addr}"
    def to_dict(self):
        return dict(addr=self.addr, fc=self.fc, fmt=self.fmt, order=self.order,
                    name=self.name, scale=self.scale, unit=self.unit, slave_id=self.slave_id,
                    description=self.description, normal_min=self.normal_min,
                    normal_max=self.normal_max, warn_min=self.warn_min, warn_max=self.warn_max)
    @classmethod
    def from_dict(cls, d):
        return cls(addr=d["addr"], fc=d["fc"], fmt=d["fmt"], order=d["order"],
                   name=d["name"], scale=d.get("scale", 1.0), unit=d.get("unit", ""),
                   slave_id=d.get("slave_id"), description=d.get("description", ""),
                   normal_min=d.get("normal_min"), normal_max=d.get("normal_max"),
                   warn_min=d.get("warn_min"), warn_max=d.get("warn_max"))

@dataclass
class ScanResult:
    addr: int
    fc: str
    slave_id: int
    exists: bool = False
    raw: Optional[List[int]] = None
    value: Optional[float] = None
    writable: Optional[bool] = None
    error: Optional[str] = None
    writable_note: Optional[str] = None
    fmt: str = "UInt16"

@dataclass
class WriteResult:
    status: str
    message: str
    addr: int = 0
    fc: str = ""
    expected: Optional[List[int]] = None
    actual: Optional[List[int]] = None
    error_code: Optional[int] = None
    old_raw: Optional[List[int]] = None
    fmt: str = "UInt16"
    order: str = "ABCD"

@dataclass
class DiscoveryResult:
    slave_id: int
    fc: str
    addr: int
    raw: List[int]
    fmt_guesses: List[tuple]

class ConnectionManager:
    def __init__(self):
        self.client = None; self.connected = False; self.mode = None; self.info = {}
        self.lock = threading.RLock()
        self.stats = {"sessions":0,"timeouts":0,"errors":0,"last_ok":0}
    def connect(self, mode, host="", port=502, com="", baud=9600):
        self.disconnect()
        try:
            if mode == "TCP": self.client = ModbusTcpClient(host, port=port, timeout=3)
            elif mode == "RTU over TCP":
                try:
                    from pymodbus.framer import FramerType; framer = FramerType.RTU
                except Exception:
                    from pymodbus.transaction import ModbusRtuFramer as framer
                self.client = ModbusTcpClient(host, port=port, framer=framer, timeout=3)
            else: self.client = ModbusSerialClient(method="rtu", port=com, baudrate=baud, stopbits=1, bytesize=8, timeout=3)
            if self.client.connect():
                self.connected = True; self.mode = mode
                self.info = {"host":host,"port":port,"com":com,"baud":baud}
                self.stats["sessions"] += 1; self.stats["last_ok"] = time.time()
                return True
        except Exception: self.stats["errors"] += 1
        self.client = None; return False
    def disconnect(self):
        with self.lock:
            if self.client:
                try: self.client.close()
                except: pass
            self.client = None; self.connected = False
    def call(self, method, *args, uid=1, **kwargs):
        with self.lock:
            if not self.client or not self.connected: return None
            for k in ("slave", "device_id", "unit", None):
                try:
                    if k is None: r = method(*args, **kwargs)
                    else: r = method(*args, **{k: uid}, **kwargs)
                    if r and not getattr(r, "isError", lambda: True)():
                        self.stats["last_ok"] = time.time()
                    return r
                except TypeError as te:
                    if "unexpected keyword" not in str(te) and "positional argument" not in str(te):
                        self.stats["errors"] += 1
                        return None
                    continue
                except Exception:
                    self.stats["errors"] += 1; return None
        return None

class RequestInspector:
    def __init__(self, maxlen=500):
        self.entries = deque(maxlen=maxlen); self.lock = threading.Lock()
    def record(self, **kw):
        with self.lock: self.entries.append(kw); return kw
    def get_all(self):
        with self.lock: return list(self.entries)
    def clear(self):
        with self.lock: self.entries.clear()

class DataLogger:
    def __init__(self, path="modbus_pro.db"):
        self.path = path; self.conn = None; self.enabled = False
        self._lock = threading.Lock(); self.retention_days = 30
        self._q = queue.Queue(); self._writer = None; self._stop = threading.Event()
        self.flush_errors = 0; self.last_flush_error = ""
    def start(self):
        try:
            self.conn = sqlite3.connect(self.path, check_same_thread=False)
            c = self.conn.cursor()
            c.execute("CREATE TABLE IF NOT EXISTS readings(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, name TEXT, addr INTEGER, fc TEXT, value REAL, raw TEXT, health TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, level TEXT, source TEXT, message TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS writes(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, name TEXT, addr INTEGER, old TEXT, new TEXT, verified INTEGER, reason TEXT)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_r_ts ON readings(ts)")
            self.conn.commit()
        except Exception as ex:
            self.last_flush_error = f"open: {ex}"; self.enabled = False; return False
        self.enabled = True; self._stop.clear()
        self._writer = threading.Thread(target=self._loop, daemon=True); self._writer.start()
        return True
    def _loop(self):
        batch = []
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=0.5); batch.append(item)
                while len(batch) < 100:
                    try: batch.append(self._q.get_nowait())
                    except queue.Empty: break
                self._flush(batch); batch = []
            except queue.Empty:
                if batch: self._flush(batch); batch = []
        if batch: self._flush(batch)
    def _flush(self, items):
        with self._lock:
            try:
                cur = self.conn.cursor()
                cur.executemany("INSERT INTO readings(ts,name,addr,fc,value,raw,health) VALUES(?,?,?,?,?,?,?)", items)
                self.conn.commit()
            except Exception as ex:
                self.flush_errors += 1; self.last_flush_error = str(ex)
    def log_reading(self, e):
        if not self.enabled: return
        raw = " ".join(f"{r:04X}" for r in e.last_raw) if e.last_raw else ""
        val = e.last_val if isinstance(e.last_val, (int, float)) else None
        try: self._q.put_nowait((time.time(), e.name, e.addr, e.fc, val, raw, e.health))
        except queue.Full: pass
    def log_event(self, level, source, message):
        if not self.enabled: return
        with self._lock:
            try:
                self.conn.execute("INSERT INTO events(ts,level,source,message) VALUES(?,?,?,?)", (time.time(), level, source, message))
                self.conn.commit()
            except Exception as ex:
                self.flush_errors += 1; self.last_flush_error = str(ex)
    def log_write(self, e, result):
        if not self.enabled: return
        with self._lock:
            try:
                self.conn.execute("INSERT INTO writes(ts,name,addr,old,new,verified,reason) VALUES(?,?,?,?,?,?,?)",
                    (time.time(), e.name, e.addr, str(result.get("old")), str(result.get("new")),
                     1 if result.get("verified") else 0, result.get("reason_text") or result.get("error") or ""))
                self.conn.commit()
            except Exception as ex:
                self.flush_errors += 1; self.last_flush_error = str(ex)
    def log_write_meta(self, name, addr, old, new, verified, reason):
        if not self.enabled: return
        with self._lock:
            try:
                self.conn.execute("INSERT INTO writes(ts,name,addr,old,new,verified,reason) VALUES(?,?,?,?,?,?,?)",
                    (time.time(), name, addr, str(old), str(new), 1 if verified else 0, reason or ""))
                self.conn.commit()
            except Exception as ex:
                self.flush_errors += 1; self.last_flush_error = str(ex)
    def query(self, sql, params=()):
        with self._lock:
            try: return self.conn.execute(sql, params).fetchall()
            except Exception as ex: return [("ERROR", str(ex))]
    def prune(self):
        cutoff = time.time() - self.retention_days * 86400
        with self._lock:
            try:
                for t in ("readings","events","writes"): self.conn.execute(f"DELETE FROM {t} WHERE ts < ?", (cutoff,))
                self.conn.commit()
            except: pass
    def stop(self):
        self._stop.set()
        if self._writer: self._writer.join(timeout=2)
        if self._writer and self._writer.is_alive():
            self.enabled = False
            return
        if self.conn:
            try: self.conn.close()
            except: pass
        self.enabled = False

class MqttBridge:
    def __init__(self):
        self.client = None; self.enabled = False; self.topic_prefix = "modbus/"
        self._q = queue.Queue(maxsize=5000); self._thread = None; self._stop = threading.Event()
        self.last_error = ""
    def connect(self, host, port=1883, username="", password="", prefix="modbus/"):
        if not HAS_MQTT: return False, "paho-mqtt not installed"
        try:
            if _MQTT_V2: self.client = mqtt_client.Client(callback_api_version=mqtt_client.CallbackAPIVersion.VERSION2)
            else: self.client = mqtt_client.Client()
            if username: self.client.username_pw_set(username, password)
            self.client.connect(host, port, keepalive=30); self.client.loop_start()
            self.enabled = True
            self.topic_prefix = prefix if prefix.endswith("/") else prefix + "/"
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True); self._thread.start()
            return True, "Connected"
        except Exception as ex:
            self.enabled = False; self.last_error = str(ex); return False, str(ex)
    def _loop(self):
        fail_count = 0
        while not self._stop.is_set():
            try:
                topic, payload = self._q.get(timeout=1)
                rc = self.client.publish(topic, payload, qos=0)
                if rc.rc != 0: fail_count += 1; self.last_error = f"publish rc={rc.rc}"
                else: fail_count = 0
            except queue.Empty: continue
            except Exception as ex:
                fail_count += 1; self.last_error = str(ex)
                if fail_count > 10: self.enabled = False; break
    def publish_reading(self, e):
        if not self.enabled: return
        try:
            payload = json.dumps({"value": e.last_val, "unit": e.unit, "addr": e.addr, "fc": e.fc, "health": e.health, "ts": time.time()})
            self._q.put_nowait((self.topic_prefix + e.name.replace(" ", "_"), payload))
        except queue.Full: pass
    def disconnect(self):
        self.enabled = False; self._stop.set()
        if self._thread: self._thread.join(timeout=2)
        if self.client:
            try: self.client.loop_stop(); self.client.disconnect()
            except: pass
        self.client = None

class PollWorker:
    def __init__(self, app):
        self.app = app; self.thread = None; self.stop_evt = threading.Event()
        self.q = queue.Queue(); self.active = False; self.interval_ms = 1000
        self._drain_scheduled = False; self._drain_lock = threading.Lock()
        self._read_once_active = False
        self._read_once_lock = threading.Lock()
    def start(self, interval_ms):
        if self.active: return
        if self.thread and self.thread.is_alive():
            self.stop_evt.set()
            self.thread.join(timeout=2)
        self.interval_ms = max(200, interval_ms)
        self.stop_evt.clear(); self.active = True
        self.thread = threading.Thread(target=self._run, daemon=True); self.thread.start()
        self._schedule_drain()
    def stop(self):
        self.active = False; self.stop_evt.set()
    def read_once(self, entries):
        with self._read_once_lock:
            if self._read_once_active:
                return
            self._read_once_active = True
        def run():
            try:
                for e in entries:
                    if self.stop_evt.is_set() and self.active: break
                    raw = self.app._read_entry_raw(e)
                    self.q.put((e, raw))
            finally:
                with self._read_once_lock:
                    self._read_once_active = False
        threading.Thread(target=run, daemon=True).start()
        self._schedule_drain()
    def _run(self):
        while not self.stop_evt.is_set():
            t0 = time.perf_counter()
            for e in list(self.app.watch):
                if self.stop_evt.is_set(): break
                raw = self.app._read_entry_raw(e)
                self.q.put((e, raw))
            elapsed = (time.perf_counter() - t0) * 1000
            self.stop_evt.wait(max(50, self.interval_ms - elapsed) / 1000.0)
    def _schedule_drain(self):
        with self._drain_lock:
            if self._drain_scheduled: return
            self._drain_scheduled = True
        def tick():
            with self._drain_lock: self._drain_scheduled = False
            self._drain()
            if self.active or not self.q.empty(): self._schedule_drain()
        try: self.app.root.after(80, tick)
        except tk.TclError: pass
    def _drain(self):
        n = 0
        while n < 300:
            try: e, raw = self.q.get_nowait()
            except queue.Empty: break
            if e in self.app.watch:
                if raw is None: e.error_count += 1
                else: self.app._apply_read_result(e, raw)
            n += 1

class WriteGuard:
    def __init__(self):
        self.min_interval_ms = 50
        self._last_write_ms = 0
        self._undo_stack = []
        self._lock = threading.Lock()
        self._emergency_locked = False
    def check_rate(self):
        with self._lock:
            now = time.time() * 1000
            wait = self.min_interval_ms - (now - self._last_write_ms)
            self._last_write_ms = now + max(0, wait)
        if wait > 0: time.sleep(wait / 1000.0)
    def set_emergency_lock(self, locked): self._emergency_locked = locked
    def is_locked(self): return self._emergency_locked
    def push_undo(self, entry, prev_value):
        try: self._undo_stack.append((entry.to_dict(), prev_value))
        except: pass
        if len(self._undo_stack) > 200: self._undo_stack.pop(0)
    def peek_undo(self): return self._undo_stack[-1] if self._undo_stack else None
    def pop_undo(self): return self._undo_stack.pop() if self._undo_stack else None
    def has_undo(self): return bool(self._undo_stack)

class Macro:
    def __init__(self, name, steps=None):
        self.name = name; self.steps = steps or []
    def to_dict(self): return {"name": self.name, "steps": self.steps}
    @classmethod
    def from_dict(cls, d): return cls(d.get("name","Macro"), d.get("steps",[]))

class MacroRunner:
    def __init__(self, app):
        self.app = app; self.running = False; self.stop_evt = threading.Event()
    def _slave_of(self, step):
        raw = step.get("slave_id")
        if raw is None or raw == "": return None
        try: return int(raw)
        except: return None
    def run(self, macro, on_log=None, on_done=None):
        if self.running: return False
        self.running = True; self.stop_evt.clear()
        def worker():
            results = []
            try:
                for i, step in enumerate(macro.steps):
                    if self.stop_evt.is_set():
                        results.append({"step": i, "ok": False, "error": "Aborted"}); break
                    action = step.get("action", "write")
                    if on_log:
                        try: self.app.root.after(0, lambda idx=i, a=action: on_log(f"  Step {idx+1}: {a}"))
                        except: pass
                    if action == "write":
                        try:
                            e = WatchEntry(int(step.get("addr", 0)), step.get("fc", "Holding Registers"),
                                           step.get("fmt", "UInt16"), step.get("order", "ABCD"),
                                           step.get("name", f"Macro_{i}"), float(step.get("scale", 1.0)),
                                           step.get("unit", ""), slave_id=self._slave_of(step))
                            self.app.write_guard.check_rate()
                            prev_raw = self.app._read_entry_raw(e)
                            prev_dec = decode_value(prev_raw, e.fmt, e.order) if prev_raw is not None else None
                            r = self.app._write_verify(e, str(step.get("value", 0)))
                            if r.get("ok") and prev_dec is not None:
                                self.app.write_guard.push_undo(e, prev_dec)
                            results.append({"step": i, "result": r})
                        except Exception as ex:
                            results.append({"step": i, "ok": False, "error": str(ex)})
                    elif action == "delay":
                        secs = float(step.get("seconds", 1))
                        if self.stop_evt.wait(secs):
                            results.append({"step": i, "ok": False, "error": "Aborted"}); break
                        results.append({"step": i, "ok": True})
                    elif action == "read":
                        try:
                            e = WatchEntry(int(step.get("addr", 0)), step.get("fc","Holding Registers"),
                                           step.get("fmt","UInt16"), step.get("order","ABCD"),
                                           step.get("name", f"Macro_{i}"), slave_id=self._slave_of(step))
                            raw = self.app._read_entry_raw(e)
                            val = decode_value(raw, e.fmt, e.order) if raw else None
                            results.append({"step": i, "value": val})
                        except Exception as ex:
                            results.append({"step": i, "ok": False, "error": str(ex)})
            except Exception as ex:
                results.append({"step": -1, "ok": False, "error": str(ex)})
            finally:
                self.running = False
                if on_done:
                    try: self.app.root.after(0, lambda: on_done(results))
                    except: pass
        threading.Thread(target=worker, daemon=True).start()
        return True
    def stop(self): self.stop_evt.set()

class RampRunner:
    def __init__(self, app):
        self.app = app; self.running = False; self.stop_evt = threading.Event()
        self._thread = None
    @staticmethod
    def _encode_step(fmt, val):
        if fmt in ("Float32", "Float64"): return str(round(val, 6))
        return str(int(round(val)))
    def run(self, entry, from_val, to_val, duration_s, steps, on_progress=None, on_done=None):
        if self.running: return False
        if self._thread and self._thread.is_alive():
            self.stop_evt.set()
            self._thread.join(timeout=2)
        self.running = True; self.stop_evt.clear()
        def worker():
            try:
                n = max(1, int(steps))
                for i in range(n + 1):
                    if self.stop_evt.is_set(): break
                    t = i / n
                    val = from_val + (to_val - from_val) * t
                    self.app.write_guard.check_rate()
                    enc = self._encode_step(entry.fmt, val)
                    r = self.app._write_verify(entry, enc)
                    if r.get("ok") and i == 0:
                        try: self.app.write_guard.push_undo(entry, r.get("old_raw"))
                        except: pass
                    if on_progress:
                        try: self.app.root.after(0, lambda v=val, rr=r: on_progress(v, rr))
                        except: pass
                    if i < n and duration_s > 0:
                        if self.stop_evt.wait(duration_s / n):
                            break
                if on_done:
                    try: self.app.root.after(0, lambda: on_done(True, ""))
                    except: pass
            except Exception as ex:
                if on_done:
                    try: self.app.root.after(0, lambda m=str(ex): on_done(False, m))
                    except: pass
            finally:
                self.running = False
        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()
        return True
    def stop(self): self.stop_evt.set()

class SmartScanner:
    def __init__(self, conn, uid_getter):
        self.conn = conn
        self._uid = uid_getter
        self.stop_evt = threading.Event()
    def _read_raw(self, fc, addr, slave_id, n=1):
        try:
            if fc == "Holding Registers":
                return self.conn.call(self.conn.client.read_holding_registers, addr, count=n, uid=slave_id)
            if fc == "Input Registers":
                return self.conn.call(self.conn.client.read_input_registers, addr, count=n, uid=slave_id)
            if fc == "Coils":
                return self.conn.call(self.conn.client.read_coils, addr, count=n, uid=slave_id)
            if fc == "Discrete Inputs":
                return self.conn.call(self.conn.client.read_discrete_inputs, addr, count=n, uid=slave_id)
        except: return None
        return None
    def _extract(self, result, fc, n=1):
        if result is None: return None
        if hasattr(result, "registers") and result.registers is not None:
            return list(result.registers)
        if hasattr(result, "bits") and result.bits is not None:
            return [1 if b else 0 for b in result.bits[:n]]
        return None
    def _probe(self, fc, addr, slave_id, test_writable, fmt="UInt16"):
        n = reg_count(fmt) if fc in ("Holding Registers","Input Registers") else 1
        result = self._read_raw(fc, addr, slave_id, n)
        if result is None:
            return ScanResult(addr=addr, fc=fc, slave_id=slave_id, exists=False,
                              error="No response (timeout).", fmt=fmt)
        if hasattr(result, "isError") and result.isError():
            return ScanResult(addr=addr, fc=fc, slave_id=slave_id, exists=False,
                              error=explain_exception(result), fmt=fmt)
        raw = self._extract(result, fc, n)
        if raw is None:
            return ScanResult(addr=addr, fc=fc, slave_id=slave_id, exists=False,
                              error="Empty response", fmt=fmt)
        val = decode_value(raw, fmt) if fc in ("Holding Registers","Input Registers") else raw[0]
        st = ScanResult(addr=addr, fc=fc, slave_id=slave_id, exists=True,
                        raw=raw, value=val, fmt=fmt)
        if test_writable and fc in WRITABLE:
            self._test_writable(st, slave_id)
        return st
    def _test_writable(self, st, slave_id):
        try:
            rb_check = self._read_raw(st.fc, st.addr, slave_id, len(st.raw))
            if rb_check is None or (hasattr(rb_check, "isError") and rb_check.isError()):
                st.writable = None
                st.writable_note = "Could not verify stability"
                return
            check_raw = self._extract(rb_check, st.fc, len(st.raw))
            if check_raw != st.raw:
                st.writable = None
                st.writable_note = "Value changing - skipped"
                return
            if st.fc == "Coils":
                r = self.conn.call(self.conn.client.write_coil, st.addr, bool(st.raw[0]), uid=slave_id)
            else:
                if len(st.raw) == 1:
                    r = self.conn.call(self.conn.client.write_register, st.addr, st.raw[0], uid=slave_id)
                else:
                    r = self.conn.call(self.conn.client.write_registers, st.addr, st.raw, uid=slave_id)
            if r is None:
                st.writable = False; st.writable_note = "No response to write test"; return
            if hasattr(r, "isError") and r.isError():
                st.writable = False; st.writable_note = explain_exception(r); return
            time.sleep(0.05)
            rb = self._read_raw(st.fc, st.addr, slave_id,
                                reg_count(st.fmt) if st.fc == "Holding Registers" else 1)
            if rb is None or (hasattr(rb, "isError") and rb.isError()):
                st.writable = True; st.writable_note = "Write OK, read-back failed"; return
            rb_raw = self._extract(rb, st.fc, len(st.raw))
            if rb_raw == st.raw:
                st.writable = True; st.writable_note = None
            else:
                st.writable = False
                st.writable_note = f"Write accepted but read-back differs"
        except Exception as e:
            st.writable = False; st.writable_note = str(e)
    def scan_range(self, fc, start, count, slave_id, test_writable, on_result, on_progress, fmt="UInt16"):
        for i in range(count):
            if self.stop_evt.is_set(): break
            addr = start + i
            try:
                st = self._probe(fc, addr, slave_id, test_writable, fmt)
            except Exception as ex:
                st = ScanResult(addr=addr, fc=fc, slave_id=slave_id, exists=False,
                                error=str(ex), fmt=fmt)
            on_result(st)
            on_progress(i + 1, count)
    def stop(self): self.stop_evt.set()

class DiscoveryScanner:
    def __init__(self, conn, uid_getter):
        self.conn = conn
        self._uid = uid_getter
        self.stop_evt = threading.Event()
    def scan_slaves(self, start=1, end=10, on_progress=None):
        found = []
        for sid in range(start, end + 1):
            if self.stop_evt.is_set(): break
            try:
                rr = self.conn.call(self.conn.client.read_holding_registers, 0, count=1, uid=sid)
                if rr and not rr.isError():
                    found.append(sid)
                    if on_progress: on_progress(sid, True)
                else:
                    if on_progress: on_progress(sid, False)
            except Exception:
                if on_progress: on_progress(sid, False)
        return found
    def scan_registers(self, slave_id, fc, start=0, count=100, step=1, on_progress=None):
        results = []
        i = 0
        while i < count:
            if self.stop_evt.is_set(): break
            addr = start + i
            raw = self._read_at(slave_id, fc, addr)
            if raw is not None:
                prev_raw = self._read_at(slave_id, fc, addr)
                guesses = FormatDetector.guess(raw, prev_raw if prev_raw != raw else None)
                if fc == "Coils":
                    guesses = [("UInt16", "ABCD", 1.0, f"Coil={'ON' if raw[0] else 'OFF'}")]
                results.append(DiscoveryResult(slave_id, fc, addr, raw, guesses))
            if on_progress: on_progress(addr, raw)
            i += step
        return results
    def _read_at(self, slave_id, fc, addr):
        try:
            if fc == "Holding Registers": method = self.conn.client.read_holding_registers
            elif fc == "Input Registers": method = self.conn.client.read_input_registers
            elif fc == "Coils": method = self.conn.client.read_coils
            elif fc == "Discrete Inputs": method = self.conn.client.read_discrete_inputs
            else: return None
            rr = self.conn.call(method, addr, count=4 if "Registers" in fc else 1, uid=slave_id)
            if rr and not rr.isError():
                if hasattr(rr, "registers"): return rr.registers
                elif hasattr(rr, "bits"): return [1 if b else 0 for b in rr.bits[:1]]
            return None
        except: return None
    def stop(self): self.stop_evt.set()

class PcomClient:
    def __init__(self, ip, port=20256, timeout=5):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.tid = 0
    def _next_tid(self):
        self.tid = (self.tid + 1) & 0xFFFF
        return self.tid
    @staticmethod
    def _checksum(payload):
        return sum(payload) & 0xFF
    def _build_frame(self, unit_id, command, data_ascii):
        ascii_body = f"/{unit_id:02X}{command}{data_ascii}".encode('ascii')
        checksum = self._checksum(ascii_body[1:])
        message = ascii_body + f"{checksum:02X}".encode('ascii') + b"\r"
        tid = self._next_tid()
        header = struct.pack('<H', tid) + b'\x65\x00' + struct.pack('<H', len(message))
        return header + message
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.ip, self.port))
    def close(self):
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None
    def write_mi(self, unit_id, address, value=0):
        data = f"{address:04X}{value & 0xFFFF:04X}"
        frame = self._build_frame(unit_id, "SW", data)
        try:
            self.sock.sendall(frame)
            self.sock.settimeout(1.0)
            resp = self.sock.recv(256)
            return b"/A" in resp
        except socket.timeout:
            return False
        except Exception:
            return False

class ZeroingEngine:
    def __init__(self, log_fn):
        self.log = log_fn
        self.stop_evt = threading.Event()
    def stop(self):
        self.stop_evt.set()
    @staticmethod
    def _pymodbus_call(client, method_name, *args, unit=1):
        method = getattr(client, method_name, None)
        if method is None: return None
        for kw in ("slave", "device_id", "unit"):
            try:
                return method(*args, **{kw: unit})
            except TypeError as te:
                msg = str(te).lower()
                if "unexpected keyword" in msg or "positional argument" in msg:
                    continue
                return None
            except Exception:
                return None
        try:
            return method(*args)
        except Exception:
            return None
    def zero_modbus_tcp(self, ip, port, unit, start, count):
        if not HAS_PYM:
            self.log(f"[{ip}] pymodbus not installed - pip install pymodbus")
            return False
        try:
            client = ModbusTcpClient(ip, port=port, timeout=3)
            if not client.connect():
                self.log(f"[{ip}] Modbus connect failed on {ip}:{port}")
                return False
            self.log(f"[{ip}] Modbus connected on port {port}")
            reg_ok = 0
            coil_ok = 0
            for addr in range(start, start + count):
                if self.stop_evt.is_set():
                    self.log(f"[{ip}] Modbus stopped by user")
                    break
                r = self._pymodbus_call(client, "write_register", addr, 0, unit=unit)
                if r is not None and not getattr(r, "isError", lambda: True)():
                    reg_ok += 1
                r = self._pymodbus_call(client, "write_coil", addr, False, unit=unit)
                if r is not None and not getattr(r, "isError", lambda: True)():
                    coil_ok += 1
            client.close()
            self.log(f"[{ip}] Modbus zeroed {reg_ok}/{count} registers, {coil_ok}/{count} coils")
            return reg_ok > 0 or coil_ok > 0
        except Exception as e:
            self.log(f"[{ip}] Modbus error: {e}")
            return False
    def _rockwell_zero_value(self, data_type):
        dt = (data_type or "").upper()
        if "[" in dt:
            dt = dt.split("[")[0]
        if dt == "BOOL":
            return False
        if dt in ("SINT", "INT", "DINT", "LINT", "USINT", "UINT", "UDINT", "ULINT"):
            return 0
        if dt in ("REAL", "LREAL"):
            return 0.0
        return None
    def _rockwell_tag_dict(self, tag):
        if isinstance(tag, dict):
            return tag
        out = {}
        if hasattr(tag, "tag"):
            out["name"] = tag.tag
        if hasattr(tag, "data_type"):
            out["data_type"] = tag.data_type
        if hasattr(tag, "dimensions"):
            out["dimensions"] = tag.dimensions
        return out
    def zero_rockwell_logix(self, ip, port):
        if not HAS_PYCOMM3:
            self.log(f"[{ip}] pycomm3 not installed - pip install pycomm3")
            return False
        try:
            with LogixDriver(ip) as plc:
                self.log(f"[{ip}] Rockwell Logix connected")
                tags = plc.get_tag_list()
                if not tags:
                    self.log(f"[{ip}] No tags found")
                    return False
                self.log(f"[{ip}] Found {len(tags)} tags")
                ok = 0
                skipped = 0
                for tag in tags:
                    if self.stop_evt.is_set():
                        self.log(f"[{ip}] Rockwell stopped by user")
                        break
                    td = self._rockwell_tag_dict(tag)
                    name = td.get("name") or ""
                    if not name:
                        continue
                    data_type = td.get("data_type") or ""
                    zero = self._rockwell_zero_value(data_type)
                    if zero is None:
                        skipped += 1
                        continue
                    dims = td.get("dimensions") or []
                    try:
                        total = 1
                        for d in dims:
                            dv = int(d)
                            if dv > 0:
                                total *= dv
                        if total > 1:
                            plc.write((name, [zero] * total))
                        else:
                            plc.write((name, zero))
                        ok += 1
                    except Exception as e:
                        skipped += 1
                        if skipped <= 10:
                            self.log(f"[{ip}]   skip {name}: {e}")
                self.log(f"[{ip}] Rockwell Logix zeroed {ok} tags, skipped {skipped}")
                return True
        except Exception as e:
            self.log(f"[{ip}] Rockwell Logix error: {e}")
            return False
    def zero_rockwell_slc(self, ip, port):
        if not HAS_PYCOMM3:
            self.log(f"[{ip}] pycomm3 not installed - pip install pycomm3")
            return False
        try:
            with SLCDriver(ip) as plc:
                self.log(f"[{ip}] Rockwell SLC/MicroLogix connected")
                data_files = ["N7", "N10", "N11", "N12", "N13", "N14", "N15",
                              "F8", "B3", "B4", "B5", "B6", "B7", "B8", "B9"]
                ok = 0
                failed = 0
                for df in data_files:
                    if self.stop_evt.is_set():
                        self.log(f"[{ip}] Rockwell stopped by user")
                        break
                    if df.startswith("N"):
                        zero = 0
                        count = 256
                    elif df.startswith("F"):
                        zero = 0.0
                        count = 256
                    elif df.startswith("B"):
                        zero = False
                        count = 16
                    else:
                        continue
                    for i in range(count):
                        if self.stop_evt.is_set():
                            break
                        addr = f"{df}:{i}" if not df.startswith("B") else f"{df}:0/{i}"
                        try:
                            plc.write(addr, zero)
                            ok += 1
                        except Exception as e:
                            failed += 1
                            if failed <= 10:
                                self.log(f"[{ip}]   fail {addr}: {e}")
                self.log(f"[{ip}] Rockwell SLC zeroed {ok} addresses, failed {failed}")
                return ok > 0
        except Exception as e:
            self.log(f"[{ip}] Rockwell SLC error: {e}")
            return False
    def zero_rockwell(self, ip, port, program_mode, driver_mode="auto"):
        if driver_mode == "logix":
            return self.zero_rockwell_logix(ip, port)
        if driver_mode == "slc":
            return self.zero_rockwell_slc(ip, port)
        if self.zero_rockwell_logix(ip, port):
            return True
        self.log(f"[{ip}] Logix failed, trying SLC/MicroLogix driver...")
        return self.zero_rockwell_slc(ip, port)
    def zero_unitronics(self, ip, port, unit, mi_start, mi_count):
        client = None
        try:
            client = PcomClient(ip, port)
            client.connect()
            self.log(f"[{ip}] Unitronics connected on {ip}:{port} (unit {unit})")
            ok = 0
            fail = 0
            for addr in range(mi_start, mi_start + mi_count):
                if self.stop_evt.is_set():
                    self.log(f"[{ip}] Unitronics stopped by user")
                    break
                if client.write_mi(unit, addr, 0):
                    ok += 1
                else:
                    fail += 1
            client.close()
            self.log(f"[{ip}] Unitronics zeroed {ok}/{mi_count} MIs (failed {fail})")
            return ok > 0
        except Exception as e:
            if client:
                client.close()
            self.log(f"[{ip}] Unitronics error: {e}")
            return False
    def zero_siemens(self, ip, rack, slot, clear_m, clear_q, clear_db, db_start, db_end, db_size):
        if not HAS_SNAP7:
            self.log(f"[{ip}] python-snap7 not installed - pip install python-snap7")
            return False
        try:
            client = snap7.client.Client()
            client.connect(ip, rack, slot)
            self.log(f"[{ip}] Siemens connected (rack={rack}, slot={slot})")
            if clear_m:
                try:
                    client.write_area(snap7.types.Areas.MK, 0, 0, bytearray(2048))
                    self.log(f"[{ip}] Siemens M area zeroed (0-2047)")
                except Exception as e:
                    self.log(f"[{ip}] Siemens M area error: {e}")
            if clear_q:
                try:
                    client.write_area(snap7.types.Areas.PA, 0, 0, bytearray(2048))
                    self.log(f"[{ip}] Siemens Q area zeroed (0-2047)")
                except Exception as e:
                    self.log(f"[{ip}] Siemens Q area error: {e}")
            if clear_db:
                db_ok = 0
                for db in range(db_start, db_end + 1):
                    if self.stop_evt.is_set(): break
                    try:
                        client.db_read(db, 0, 1)
                        client.db_write(db, 0, bytearray(db_size))
                        db_ok += 1
                    except Exception:
                        pass
                self.log(f"[{ip}] Siemens zeroed {db_ok} DBs (range {db_start}-{db_end})")
            client.disconnect()
            return True
        except Exception as e:
            self.log(f"[{ip}] Siemens error: {e}")
            return False

class ZeroingWindow(tk.Toplevel):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.title("Multi-Protocol Zeroing")
        self.geometry("920x780")
        self.app = app
        self.engine = None
        self.running = False
        self._log_queue = queue.Queue()
        self._build()
        self._poll_log()
    def _poll_log(self):
        try:
            while True:
                line = self._log_queue.get_nowait()
                try:
                    self.log_text.configure(state="normal")
                    self.log_text.insert(tk.END, line)
                    self.log_text.see(tk.END)
                    self.log_text.configure(state="disabled")
                except: pass
        except queue.Empty:
            pass
        try:
            self.after(100, self._poll_log)
        except: pass
    def _build(self):
        top = ttk.LabelFrame(self, text="Protocol", padding=6)
        top.pack(fill=tk.X, padx=8, pady=6)
        self.proto_var = tk.StringVar(value="Modbus TCP")
        for i, p in enumerate(ZERO_PROTOCOLS):
            ttk.Radiobutton(top, text=p, variable=self.proto_var, value=p,
                            command=self._on_proto_change).grid(row=0, column=i, padx=10, sticky="w")
        mid = ttk.Frame(self); mid.pack(fill=tk.BOTH, expand=False, padx=8, pady=4)
        ipf = ttk.LabelFrame(mid, text="Target IPs (one per line)", padding=6)
        ipf.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,4))
        self.ip_text = tk.Text(ipf, height=6, width=30)
        self.ip_text.pack(fill=tk.BOTH, expand=True)
        self.ip_text.insert("1.0", "192.168.1.10")
        pf = ttk.LabelFrame(mid, text="Parameters", padding=6)
        pf.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(4,0))
        self.param_frame = pf
        self.param_widgets = {}
        self._build_params()
        warn = ttk.Label(self, text="WARNING: This will write 0 to device memory. Destructive.",
                         foreground="#f55", font=("Segoe UI", 9, "bold"))
        warn.pack(fill=tk.X, padx=8, pady=2)
        btnf = ttk.Frame(self); btnf.pack(fill=tk.X, padx=8, pady=4)
        ttk.Button(btnf, text="Start Zeroing", command=self._start).pack(side=tk.LEFT, padx=4)
        ttk.Button(btnf, text="Stop", command=self._stop).pack(side=tk.LEFT, padx=4)
        ttk.Button(btnf, text="Clear Log", command=self._clear_log).pack(side=tk.LEFT, padx=4)
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(btnf, textvariable=self.status_var, foreground="#8cf").pack(side=tk.RIGHT, padx=8)
        logf = ttk.LabelFrame(self, text="Log", padding=4)
        logf.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        self.log_text = tk.Text(logf, height=15, state="disabled", font=("Consolas", 9))
        sc = ttk.Scrollbar(logf, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sc.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sc.pack(side=tk.RIGHT, fill=tk.Y)
    def _clear_param_frame(self):
        for w in self.param_frame.winfo_children(): w.destroy()
        self.param_widgets.clear()
    def _add_param(self, row, label, key, default, width=12):
        ttk.Label(self.param_frame, text=label).grid(row=row, column=0, sticky="w", padx=4, pady=2)
        var = tk.StringVar(value=str(default))
        ttk.Entry(self.param_frame, textvariable=var, width=width).grid(row=row, column=1, sticky="w", padx=4, pady=2)
        self.param_widgets[key] = var
    def _add_check(self, row, label, key, default=True):
        var = tk.BooleanVar(value=default)
        ttk.Checkbutton(self.param_frame, text=label, variable=var).grid(row=row, column=0, columnspan=2, sticky="w", padx=4, pady=2)
        self.param_widgets[key] = var
    def _add_combo(self, row, label, key, values, default):
        ttk.Label(self.param_frame, text=label).grid(row=row, column=0, sticky="w", padx=4, pady=2)
        var = tk.StringVar(value=default)
        ttk.Combobox(self.param_frame, textvariable=var, values=values, width=10, state="readonly").grid(row=row, column=1, sticky="w", padx=4, pady=2)
        self.param_widgets[key] = var
    def _build_params(self):
        self._clear_param_frame()
        p = self.proto_var.get()
        if p == "Modbus TCP":
            self._add_param(0, "Port:", "port", 502)
            self._add_param(1, "Unit ID:", "unit", 1)
            self._add_param(2, "Start Address:", "start", 0)
            self._add_param(3, "Count:", "count", 100)
        elif p == "Rockwell EtherNet/IP":
            self._add_combo(0, "Driver:", "driver", ["Auto", "Logix", "SLC"], "Auto")
            self._add_param(1, "Port (ignored):", "port", 44818)
            self._add_check(2, "Set PROGRAM mode first (not supported)", "program_mode", False)
        elif p == "Unitronics PCOM":
            self._add_param(0, "Port:", "port", 20256)
            self._add_param(1, "Unit ID:", "unit", 1)
            self._add_param(2, "MI Start:", "mi_start", 0)
            self._add_param(3, "MI Count:", "mi_count", 100)
        elif p == "Siemens S7":
            self._add_param(0, "Port (S7 default 102):", "port", 102)
            self._add_param(1, "Rack:", "rack", 0)
            self._add_param(2, "Slot:", "slot", 1)
            self._add_check(3, "Clear M area", "clear_m", True)
            self._add_check(4, "Clear Q area", "clear_q", True)
            self._add_check(5, "Clear DB areas", "clear_db", False)
            self._add_param(6, "DB Start:", "db_start", 1)
            self._add_param(7, "DB End:", "db_end", 20)
            self._add_param(8, "DB Size (bytes):", "db_size", 1024)
    def _on_proto_change(self):
        self._build_params()
    def _log(self, msg):
        try:
            self._log_queue.put_nowait(f"[{datetime.now():%H:%M:%S}] {msg}\n")
        except: pass
    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")
    def _get_params(self):
        out = {}
        for k, v in self.param_widgets.items():
            if isinstance(v, tk.BooleanVar): out[k] = v.get()
            else: out[k] = v.get()
        return out
    def _start(self):
        if self.running:
            messagebox.showinfo("Running", "Zeroing already in progress", parent=self)
            return
        if not messagebox.askyesno("Confirm",
                "This will write 0 to device memory.\n\nContinue?",
                parent=self):
            return
        ips = [line.strip() for line in self.ip_text.get("1.0", tk.END).splitlines() if line.strip()]
        if not ips:
            messagebox.showwarning("No IPs", "Enter at least one IP address", parent=self)
            return
        proto = self.proto_var.get()
        params = self._get_params()
        self.engine = ZeroingEngine(self._log)
        self.running = True
        self.status_var.set(f"Running {proto}...")
        self._log(f"=== Starting {proto} for {len(ips)} device(s) ===")
        def worker():
            try:
                for ip in ips:
                    if self.engine.stop_evt.is_set(): break
                    self._log(f"--- {ip} ---")
                    if proto == "Modbus TCP":
                        self.engine.zero_modbus_tcp(ip, int(params["port"]), int(params["unit"]),
                                                    int(params["start"]), int(params["count"]))
                    elif proto == "Rockwell EtherNet/IP":
                        driver = params.get("driver", "Auto").lower()
                        self.engine.zero_rockwell(ip, int(params["port"]), bool(params["program_mode"]), driver_mode=driver)
                    elif proto == "Unitronics PCOM":
                        self.engine.zero_unitronics(ip, int(params["port"]), int(params["unit"]),
                                                    int(params["mi_start"]), int(params["mi_count"]))
                    elif proto == "Siemens S7":
                        self.engine.zero_siemens(ip, int(params["rack"]), int(params["slot"]),
                                                 bool(params["clear_m"]), bool(params["clear_q"]),
                                                 bool(params["clear_db"]), int(params["db_start"]),
                                                 int(params["db_end"]), int(params["db_size"]))
                self._log("=== Done ===")
            except Exception as e:
                self._log(f"[!] Fatal error: {e}")
            finally:
                self.running = False
                status = "Done" if not self.engine.stop_evt.is_set() else "Stopped"
                try: self.after(0, lambda s=status: self.status_var.set(s))
                except: pass
        threading.Thread(target=worker, daemon=True).start()
    def _stop(self):
        if self.engine: self.engine.stop()
        self.status_var.set("Stopping...")

class StartupDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Modbus Pro - Connect"); self.geometry("560x620")
        self.resizable(False, False); self.result = None
        self.configure(bg="#1e1e2e"); self._build()
        self.lift(); self.attributes('-topmost', True); self.after(500, lambda: self.attributes('-topmost', False)); self.focus_force(); self.grab_set(); self.wait_window(self)
    def _build(self):
        f = ttk.Frame(self, padding=18); f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text="Modbus Pro Control Center", font=("Segoe UI", 20, "bold")).pack(pady=(0,2))
        ttk.Label(f, text="Scan / Write / Verify - v9.4", foreground="#8cf").pack(pady=(0,12))
        nb = ttk.Notebook(f); nb.pack(fill=tk.BOTH, expand=True)
        ct = ttk.Frame(nb, padding=10); nb.add(ct, text="Connection")
        g = ttk.Frame(ct); g.pack(fill=tk.X)
        def row(r, label, var, values=None):
            ttk.Label(g, text=label).grid(row=r, column=0, sticky="w", pady=3)
            w = ttk.Combobox(g, textvariable=var, values=values, width=26, state="readonly") if values else ttk.Entry(g, textvariable=var, width=28)
            w.grid(row=r, column=1, padx=4, sticky="ew"); return w
        self.mode_var = tk.StringVar(value="TCP"); self.host_var = tk.StringVar(value="127.0.0.1")
        self.port_var = tk.StringVar(value="502"); self.com_var = tk.StringVar(value="COM1")
        self.baud_var = tk.StringVar(value="9600"); self.slave_var = tk.StringVar(value="1")
        row(0, "Mode:", self.mode_var, ["TCP","RTU over TCP","RTU"])
        self.host_entry = row(1, "Host / IP:", self.host_var)
        row(2, "Port:", self.port_var); row(3, "COM Port:", self.com_var)
        row(4, "Baudrate:", self.baud_var, ["9600","19200","38400","57600","115200"])
        row(5, "Slave ID:", self.slave_var)
        g.columnconfigure(1, weight=1)
        ttk.Separator(ct).pack(fill=tk.X, pady=10)
        self.reconnect_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ct, text="Auto-reconnect on connection loss", variable=self.reconnect_var).pack(anchor="w", pady=2)
        btns = ttk.Frame(ct); btns.pack(fill=tk.X, pady=(10,0))
        ttk.Button(btns, text="Test", command=self._test).pack(side=tk.LEFT)
        lt = ttk.Frame(nb, padding=10); nb.add(lt, text="Logger")
        self.logger_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(lt, text="Start SQLite data logger", variable=self.logger_var).pack(anchor="w", pady=2)
        lg = ttk.Frame(lt); lg.pack(fill=tk.X, pady=6)
        ttk.Label(lg, text="DB path:").grid(row=0, column=0, sticky="w")
        self.logger_path_var = tk.StringVar(value="modbus_pro.db")
        ttk.Entry(lg, textvariable=self.logger_path_var, width=30).grid(row=0, column=1, padx=4, sticky="ew")
        ttk.Label(lg, text="Retention (days):").grid(row=1, column=0, sticky="w", pady=4)
        self.logger_days_var = tk.StringVar(value="30")
        ttk.Entry(lg, textvariable=self.logger_days_var, width=8).grid(row=1, column=1, padx=4, sticky="w")
        lg.columnconfigure(1, weight=1)
        mt = ttk.Frame(nb, padding=10); nb.add(mt, text="MQTT (optional)")
        self.mqtt_enable_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(mt, text="Publish readings to MQTT broker", variable=self.mqtt_enable_var).pack(anchor="w", pady=2)
        mg = ttk.Frame(mt); mg.pack(fill=tk.X, pady=6)
        self.mqtt_host_var = tk.StringVar(value="localhost"); self.mqtt_port_var = tk.StringVar(value="1883")
        self.mqtt_user_var = tk.StringVar(value=""); self.mqtt_pass_var = tk.StringVar(value="")
        self.mqtt_prefix_var = tk.StringVar(value="modbus/")
        for i, (lbl, v) in enumerate([("Host:", self.mqtt_host_var), ("Port:", self.mqtt_port_var),
                                      ("Username:", self.mqtt_user_var), ("Password:", self.mqtt_pass_var),
                                      ("Topic prefix:", self.mqtt_prefix_var)]):
            ttk.Label(mg, text=lbl).grid(row=i, column=0, sticky="w", pady=2)
            ent = ttk.Entry(mg, textvariable=v, width=30, show="*" if lbl == "Password:" else "")
            ent.grid(row=i, column=1, padx=4, sticky="ew")
        mg.columnconfigure(1, weight=1)
        bot = ttk.Frame(f); bot.pack(fill=tk.X, pady=(12,0))
        ttk.Button(bot, text="Cancel", command=self._cancel).pack(side=tk.RIGHT, padx=4)
        ttk.Button(bot, text="Connect", command=self._ok).pack(side=tk.RIGHT)
        self.host_entry.focus_set()
        self.bind("<Return>", lambda e: self._ok()); self.bind("<Escape>", lambda e: self._cancel())
    def _collect(self):
        return {"mode": self.mode_var.get(), "host": self.host_var.get().strip(),
                "port": int(self.port_var.get().strip() or "502"), "com": self.com_var.get().strip(),
                "baud": int(self.baud_var.get().strip() or "9600"), "slave": int(self.slave_var.get().strip() or "1"),
                "auto_reconnect": self.reconnect_var.get(),
                "logger": self.logger_var.get(), "logger_path": self.logger_path_var.get().strip() or "modbus_pro.db",
                "logger_days": int(self.logger_days_var.get().strip() or "30"),
                "mqtt_enable": self.mqtt_enable_var.get(), "mqtt_host": self.mqtt_host_var.get().strip(),
                "mqtt_port": int(self.mqtt_port_var.get().strip() or "1883"),
                "mqtt_user": self.mqtt_user_var.get().strip(), "mqtt_pass": self.mqtt_pass_var.get(),
                "mqtt_prefix": self.mqtt_prefix_var.get().strip() or "modbus/"}
    def _test(self):
        try: params = self._collect()
        except ValueError as e:
            messagebox.showerror("Invalid", str(e), parent=self); return
        if not HAS_PYM:
            messagebox.showerror("pymodbus", "pip install 'pymodbus>=3.0'", parent=self); return
        def run():
            client = None
            try:
                if params["mode"] == "RTU":
                    client = ModbusSerialClient(method="rtu", port=params["com"], baudrate=params["baud"], timeout=2)
                else: client = ModbusTcpClient(params["host"], port=params["port"], timeout=2)
                if not client.connect():
                    self.after(0, lambda: messagebox.showerror("Test", "Connection refused", parent=self)); return
                for kw in ("slave","device_id","unit"):
                    try:
                        rr = client.read_holding_registers(0, count=1, **{kw: params["slave"]})
                        if rr and not rr.isError():
                            self.after(0, lambda regs=rr.registers: messagebox.showinfo("Test", f"Connected. Slave {params['slave']}: {regs}", parent=self))
                            return
                        break
                    except TypeError: continue
                self.after(0, lambda: messagebox.showinfo("Test", "Port open, slave not responding", parent=self))
            except Exception as ex:
                msg = str(ex)
                try: self.after(0, lambda m=msg: messagebox.showerror("Test", m, parent=self))
                except (tk.TclError, RuntimeError): pass
            finally:
                if client:
                    try: client.close()
                    except: pass
        threading.Thread(target=run, daemon=True).start()
    def _ok(self):
        try: self.result = self._collect(); self.destroy()
        except ValueError as e: messagebox.showerror("Invalid", str(e), parent=self)
    def _cancel(self): self.result = None; self.destroy()

class WatchDialog(tk.Toplevel):
    def __init__(self, parent, entry=None, existing_names=None, preset_addr=None, preset_fc=None, preset_slave=None, preset_fmt=None):
        super().__init__(parent)
        self.title("Register Configuration"); self.geometry("560x680")
        self.result = None; self.entry = entry; self.existing = existing_names or set()
        self.preset_addr = preset_addr; self.preset_fc = preset_fc
        self.preset_slave = preset_slave; self.preset_fmt = preset_fmt
        self.transient(parent); self.grab_set(); self._build(); self.wait_window(self)
    def _build(self):
        main = ttk.Frame(self, padding=10); main.pack(fill=tk.BOTH, expand=True)
        nb = ttk.Notebook(main); nb.pack(fill=tk.BOTH, expand=True)
        basic = ttk.Frame(nb, padding=10); nb.add(basic, text="Basic")
        adv = ttk.Frame(nb, padding=10); nb.add(adv, text="Advanced")
        e = self.entry
        if e and e.slave_id is not None: slave_default = str(e.slave_id)
        elif self.preset_slave is not None: slave_default = str(self.preset_slave)
        else: slave_default = ""
        self.var = {"name": tk.StringVar(value=e.name if e else ""),
                    "addr": tk.StringVar(value=str(e.addr) if e else str(self.preset_addr if self.preset_addr is not None else 0)),
                    "fc": tk.StringVar(value=e.fc if e else (self.preset_fc or "Holding Registers")),
                    "fmt": tk.StringVar(value=e.fmt if e else (self.preset_fmt or "UInt16")),
                    "order": tk.StringVar(value=e.order if e else "ABCD"),
                    "scale": tk.StringVar(value=str(e.scale) if e else "1.0"),
                    "unit": tk.StringVar(value=e.unit if e else ""),
                    "slave": tk.StringVar(value=slave_default),
                    "nmin": tk.StringVar(value=str(e.normal_min) if e and e.normal_min is not None else ""),
                    "nmax": tk.StringVar(value=str(e.normal_max) if e and e.normal_max is not None else ""),
                    "wmin": tk.StringVar(value=str(e.warn_min) if e and e.warn_min is not None else ""),
                    "wmax": tk.StringVar(value=str(e.warn_max) if e and e.warn_max is not None else "")}
        rows = [("Name","name"),("Address","addr"),("Function","fc"),("Format","fmt"),
                ("Byte Order","order"),("Scale","scale"),("Unit","unit"),("Slave ID","slave")]
        for i, (label, key) in enumerate(rows):
            ttk.Label(basic, text=label+":").grid(row=i, column=0, sticky="w", pady=4)
            if key == "fc":
                ttk.Combobox(basic, textvariable=self.var[key], values=FC_LIST, width=28, state="readonly").grid(row=i, column=1, padx=4, sticky="w")
            elif key == "fmt":
                ttk.Combobox(basic, textvariable=self.var[key], values=FORMATS, width=28, state="readonly").grid(row=i, column=1, padx=4, sticky="w")
            elif key == "order":
                ttk.Combobox(basic, textvariable=self.var[key], values=BYTE_ORDERS, width=28, state="readonly").grid(row=i, column=1, padx=4, sticky="w")
            else:
                ttk.Entry(basic, textvariable=self.var[key], width=30).grid(row=i, column=1, padx=4, sticky="w")
        ttk.Label(basic, text="(leave Slave blank to use connection slave)",
                  foreground="#888", font=("Segoe UI", 8)).grid(row=len(rows), column=1, sticky="w")
        ttk.Label(basic, text="Preset:").grid(row=len(rows)+1, column=0, sticky="w", pady=(12,4))
        preset_var = tk.StringVar()
        cb = ttk.Combobox(basic, textvariable=preset_var, values=list(REGISTER_PRESETS.keys()), width=28, state="readonly")
        cb.grid(row=len(rows)+1, column=1, padx=4, sticky="w")
        def _apply(_):
            k = preset_var.get()
            if k:
                self.var["name"].set(k)
                desc_text.delete("1.0", "end"); desc_text.insert("1.0", REGISTER_PRESETS[k])
        cb.bind("<<ComboboxSelected>>", _apply)
        ttk.Label(adv, text="Description:").grid(row=0, column=0, sticky="nw", pady=4)
        desc_text = tk.Text(adv, height=3, width=45, wrap="word")
        desc_text.grid(row=0, column=1, padx=4, pady=4)
        if e and e.description: desc_text.insert("1.0", e.description)
        ttk.Separator(adv).grid(row=1, column=0, columnspan=2, sticky="ew", pady=8)
        ttk.Label(adv, text="Critical Range:", font=("Segoe UI", 9, "bold")).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4,2))
        ttk.Label(adv, text="Min:").grid(row=3, column=0, sticky="w", pady=2)
        ttk.Entry(adv, textvariable=self.var["nmin"], width=15).grid(row=3, column=1, sticky="w", padx=4)
        ttk.Label(adv, text="Max:").grid(row=4, column=0, sticky="w", pady=2)
        ttk.Entry(adv, textvariable=self.var["nmax"], width=15).grid(row=4, column=1, sticky="w", padx=4)
        ttk.Label(adv, text="Warning Range:", font=("Segoe UI", 9, "bold")).grid(row=5, column=0, columnspan=2, sticky="w", pady=(8,2))
        ttk.Label(adv, text="Min:").grid(row=6, column=0, sticky="w", pady=2)
        ttk.Entry(adv, textvariable=self.var["wmin"], width=15).grid(row=6, column=1, sticky="w", padx=4)
        ttk.Label(adv, text="Max:").grid(row=7, column=0, sticky="w", pady=2)
        ttk.Entry(adv, textvariable=self.var["wmax"], width=15).grid(row=7, column=1, sticky="w", padx=4)
        self._desc_text = desc_text
        btns = ttk.Frame(main); btns.pack(fill=tk.X, pady=10)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btns, text="OK", command=self._ok).pack(side=tk.RIGHT)
    @staticmethod
    def _pf(s):
        s = (s or "").strip()
        if not s: return None
        try: return float(s)
        except: return None
    def _ok(self):
        try:
            addr = int(self.var["addr"].get())
            if not 0 <= addr <= 65535:
                messagebox.showerror("Invalid", "Address 0..65535", parent=self); return
            name = self.var["name"].get().strip() or f"Reg_{addr}"
            if name in self.existing:
                messagebox.showerror("Invalid", "Name already exists", parent=self); return
            slave_str = self.var["slave"].get().strip()
            if slave_str:
                slave = int(slave_str)
                if not 0 <= slave <= 255:
                    messagebox.showerror("Invalid", "Slave 0..255", parent=self); return
            else: slave = None
            desc = self._desc_text.get("1.0", "end-1c").strip()
            self.result = WatchEntry(addr=addr, fc=self.var["fc"].get(), fmt=self.var["fmt"].get(),
                order=self.var["order"].get(), name=name, scale=float(self.var["scale"].get() or 1.0),
                unit=self.var["unit"].get().strip(), slave_id=slave, description=desc,
                normal_min=self._pf(self.var["nmin"].get()), normal_max=self._pf(self.var["nmax"].get()),
                warn_min=self._pf(self.var["wmin"].get()), warn_max=self._pf(self.var["wmax"].get()))
            self.destroy()
        except Exception as ex: messagebox.showerror("Invalid", str(ex), parent=self)

class BitEditorDialog(tk.Toplevel):
    def __init__(self, parent, app, entry):
        super().__init__(parent)
        self.title(f"Bits - {entry.name} @ {entry.addr}")
        self.geometry("400x540")
        self.app, self.entry = app, entry
        self.transient(parent)
        self.bits = [tk.BooleanVar(value=False) for _ in range(16)]
        self._build()
    def _build(self):
        f = ttk.Frame(self, padding=8); f.pack(fill=tk.BOTH, expand=True)
        raw = self.app._read_entry_raw(self.entry)
        if raw:
            v = raw[0]
            for i in range(16): self.bits[i].set(bool((v >> i) & 1))
        ttk.Label(f, text="Check the bits you want set to 1.",
                  foreground="#888", font=("Segoe UI", 9)).pack(pady=(0,8))
        grid = ttk.Frame(f); grid.pack(pady=5)
        for i in range(16):
            r = 15 - i
            ttk.Label(grid, text=f"Bit {i:2d}:").grid(row=r, column=0, sticky="e", padx=2, pady=1)
            ttk.Checkbutton(grid, variable=self.bits[i]).grid(row=r, column=1, padx=2)
            ttk.Label(grid, text=f"({1 << i})").grid(row=r, column=2, sticky="w", padx=4)
        self._val_lbl = tk.StringVar(value="0")
        ttk.Label(f, text="Final value:", foreground="#888").pack(pady=(10,2))
        ttk.Label(f, textvariable=self._val_lbl, font=("Consolas", 14, "bold"), foreground="#00d4ff").pack()
        for b in self.bits:
            b.trace("w", lambda *a: self._update_val())
        ttk.Button(f, text="Write to PLC", command=self._write).pack(pady=10)
        ttk.Button(f, text="Close", command=self.destroy).pack()
    def _update_val(self):
        v = sum((1 << i) for i in range(16) if self.bits[i].get())
        self._val_lbl.set(f"{v}   (0x{v:04X})")
    def _write(self):
        val = sum((1 << i) for i in range(16) if self.bits[i].get())
        self.app._do_write_and_show(self.entry, str(val),
                                    on_done=lambda e, r, w=self: (w.destroy() if r.get("verified") else None))

class RegisterDetailsPanel(ttk.LabelFrame):
    def __init__(self, parent, app):
        super().__init__(parent, text="Register Details", padding=8)
        self.app = app; self.current = None; self._build()
    def _build(self):
        self.title_var = tk.StringVar(value="(select a register above)")
        self.subtitle_var = tk.StringVar(value="")
        self.value_var = tk.StringVar(value="\u2014"); self.scaled_var = tk.StringVar(value="")
        self.raw_var = tk.StringVar(value=""); self.health_var = tk.StringVar(value="")
        self.trend_var = tk.StringVar(value=""); self.range_var = tk.StringVar(value="")
        self.observed_var = tk.StringVar(value=""); self.updated_var = tk.StringVar(value="")
        self.desc_var = tk.StringVar(value="")
        top = ttk.Frame(self); top.pack(fill=tk.X)
        ttk.Label(top, textvariable=self.title_var, font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
        ttk.Label(top, text="  \u2022  ", foreground="#888").pack(side=tk.LEFT)
        ttk.Label(top, textvariable=self.subtitle_var, foreground="#888").pack(side=tk.LEFT)
        grid = ttk.Frame(self); grid.pack(fill=tk.X, pady=6)
        def row(r, label, var, font=("Consolas", 10), fg=None):
            ttk.Label(grid, text=label, foreground="#888").grid(row=r, column=0, sticky="w", padx=(0,8))
            lbl = ttk.Label(grid, textvariable=var, font=font)
            if fg: lbl.configure(foreground=fg)
            lbl.grid(row=r, column=1, sticky="w"); return lbl
        row(0, "Value:",  self.value_var,  ("Consolas", 14, "bold"), "#00d4ff")
        row(1, "Scaled:", self.scaled_var, ("Consolas", 11))
        row(2, "Raw:",    self.raw_var,    ("Consolas", 10))
        self._health_lbl = row(3, "Health:", self.health_var, ("Segoe UI", 10, "bold"))
        row(4, "Trend:",  self.trend_var,  ("Consolas", 10))
        row(5, "Normal:", self.range_var,  ("Consolas", 9))
        row(6, "Observed:", self.observed_var, ("Consolas", 9))
        row(7, "Updated:", self.updated_var, ("Consolas", 9))
        ttk.Label(self, text="Description:", foreground="#888").pack(anchor="w", pady=(6,0))
        ttk.Label(self, textvariable=self.desc_var, wraplength=900, font=("Segoe UI", 9)).pack(anchor="w", padx=8)
    def show(self, entry):
        self.current = entry
        if not entry:
            self.title_var.set("(select a register above)"); self.subtitle_var.set(""); return
        self.title_var.set(entry.name)
        slave_disp = f"  \u2022  Slave {entry.slave_id}" if entry.slave_id is not None else ""
        self.subtitle_var.set(f"{entry.fc} @ {entry.addr}  \u2022  {entry.fmt}  \u2022  {entry.order}{slave_disp}")
        if entry.last_val is None:
            self.value_var.set("\u2014"); self.scaled_var.set(""); self.raw_var.set("")
        else:
            self.value_var.set(f"{entry.last_val} {entry.unit}")
            if entry.scale != 1.0 and isinstance(entry.last_val, (int, float)):
                self.scaled_var.set(f"{fmt_scale(entry.last_val, entry.scale):.4f} {entry.unit}  (x {entry.scale})")
            else: self.scaled_var.set("(no scaling)")
            self.raw_var.set(" ".join(f"{r:04X}" for r in entry.last_raw) if entry.last_raw else "\u2014")
        self.health_var.set(entry.health)
        h = entry.health
        fg = "#4c4" if h.startswith("\u2713") else "#fc4" if h.startswith("\u26a0") else "#f55" if h.startswith("\U0001f6a8") else "#888"
        try: self._health_lbl.configure(foreground=fg)
        except: pass
        self.trend_var.set(entry.trend)
        ranges = []
        if entry.normal_min is not None or entry.normal_max is not None:
            ranges.append(f"normal: {entry.normal_min or '-inf'} to {entry.normal_max or '+inf'}")
        if entry.warn_min is not None or entry.warn_max is not None:
            ranges.append(f"warn: {entry.warn_min or '-inf'} to {entry.warn_max or '+inf'}")
        self.range_var.set(" | ".join(ranges) or "(not configured)")
        if entry.min_observed is not None:
            self.observed_var.set(f"min {entry.min_observed:.3f}  max {entry.max_observed:.3f}  reads {entry.read_count}  errors {entry.error_count}")
        else: self.observed_var.set(f"reads {entry.read_count}  errors {entry.error_count}")
        self.updated_var.set(f"{fmt_uptime(time.time() - entry.last_read_at)} ago" if entry.last_read_at else "never")
        self.desc_var.set(entry.description or "(no description)")

class TrafficInspector(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app; self.max_rows = 1000; self._build()
    def _build(self):
        ctl = ttk.Frame(self); ctl.pack(fill=tk.X, pady=3)
        ttk.Button(ctl, text="Refresh", command=self.refresh).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Clear", command=self._clear).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Export", command=self._export).pack(side=tk.LEFT, padx=2)
        self.autoscroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctl, text="Auto-scroll", variable=self.autoscroll_var).pack(side=tk.LEFT, padx=8)
        self.filter_var = tk.StringVar(); self.filter_var.trace("w", lambda *a: self.refresh())
        ttk.Label(ctl, text="Filter:").pack(side=tk.LEFT, padx=(15,2))
        ttk.Entry(ctl, textvariable=self.filter_var, width=20).pack(side=tk.LEFT)
        self.stats_var = tk.StringVar(value="0 transactions")
        ttk.Label(ctl, textvariable=self.stats_var, foreground="#8cf").pack(side=tk.RIGHT, padx=8)
        cols = ("time","fc","op","addr","count","dur","status","response","meaning")
        tv_frame = ttk.Frame(self); tv_frame.pack(fill=tk.BOTH, expand=True)
        self.tv = ttk.Treeview(tv_frame, columns=cols, show="headings", height=20)
        widths = {"time":85,"fc":55,"op":210,"addr":70,"count":55,"dur":65,"status":65,"response":180,"meaning":320}
        heads = {"time":"Time","fc":"FC","op":"Operation","addr":"Address","count":"Count",
                 "dur":"Dur (ms)","status":"Status","response":"Response (hex)","meaning":"Meaning"}
        for c in cols:
            self.tv.heading(c, text=heads[c]); self.tv.column(c, width=widths[c], anchor="w" if c in ("op","response","meaning") else "center")
        self.tv.tag_configure("ok", foreground="#4c4"); self.tv.tag_configure("err", foreground="#f55")
        self.tv.tag_configure("write", background="#2a3a5a")
        sc = ttk.Scrollbar(tv_frame, orient="vertical", command=self.tv.yview)
        self.tv.configure(yscrollcommand=sc.set)
        self.tv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); sc.pack(side=tk.RIGHT, fill=tk.Y)
    def add(self, rec):
        if not self.winfo_exists(): return
        self.tv.insert("", 0, values=self._format_row(rec), tags=self._tags(rec))
        children = self.tv.get_children()
        if len(children) > self.max_rows:
            for iid in children[self.max_rows:]: self.tv.delete(iid)
        self.stats_var.set(f"{len(self.tv.get_children())} transactions")
        if self.autoscroll_var.get() and self.tv.get_children(): self.tv.see(self.tv.get_children()[0])
    def _tags(self, rec):
        t = ("err",) if not rec.get("ok") else ("ok",)
        if rec.get("fc_num") in (5,6,15,16): t = t + ("write",)
        return t
    def _format_row(self, rec):
        ts = rec["time"].strftime("%H:%M:%S.%f")[:-3]
        addr_str = f"{rec['addr']}" if rec.get("addr") is not None else "\u2014"
        if rec.get("count") is not None and rec["addr"] is not None: addr_str = f"{rec['addr']}+{rec['count']}"
        return (ts, f"FC{rec['fc_num']:02d}" if rec.get('fc_num') else "\u2014",
                rec.get("fc_desc") or "\u2014", addr_str, rec.get("count") or "\u2014", rec.get("ms", 0),
                "OK" if rec.get("ok") else "ERR", (rec.get("response") or "\u2014")[:60], self._meaning(rec))
    def _meaning(self, rec):
        parts = []
        if rec.get("values") is not None:
            v = rec["values"]
            parts.append("sent: " + (" ".join(f"{x:04X}" for x in v[:6]) if isinstance(v, list) else f"wrote {v}"))
        if rec.get("response") and rec.get("ok") and rec.get("fc_num") in (1,2,3,4):
            parts.append("read: " + rec["response"][:40])
        if rec.get("error"): parts.append(f"error: {rec['error'][:80]}")
        return " | ".join(parts) if parts else "\u2014"
    def _clear(self):
        self.tv.delete(*self.tv.get_children()); self.app.inspector.clear(); self.stats_var.set("0 transactions")
    def _export(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path: return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["Time","FC","Operation","Address","Count","Duration","Status","Response","Meaning"])
            for iid in self.tv.get_children(): w.writerow(self.tv.item(iid, "values"))
        self.app.log(f"Traffic exported: {path}")
    def refresh(self):
        f = self.filter_var.get().lower().strip()
        self.tv.delete(*self.tv.get_children())
        for rec in self.app.inspector.get_all():
            row = self._format_row(rec)
            if f and not any(f in str(v).lower() for v in row): continue
            self.tv.insert("", 0, values=row, tags=self._tags(rec))
        self.stats_var.set(f"{len(self.tv.get_children())} transactions")

class ScannerDialog(tk.Toplevel):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.title("Network Scanner"); self.geometry("580x480"); self.app = app
        f = ttk.Frame(self, padding=8); f.pack(fill=tk.BOTH, expand=True)
        top = ttk.Frame(f); top.pack(fill=tk.X)
        ttk.Label(top, text="Subnet (x.x.x):").pack(side=tk.LEFT)
        self.subnet_var = tk.StringVar(value=self._detect())
        ttk.Entry(top, textvariable=self.subnet_var, width=15).pack(side=tk.LEFT, padx=3)
        ttk.Label(top, text="Port:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="502"); ttk.Entry(top, textvariable=self.port_var, width=6).pack(side=tk.LEFT)
        ttk.Button(top, text="Scan", command=self._start).pack(side=tk.LEFT, padx=4)
        self.prog = ttk.Progressbar(f, maximum=254); self.prog.pack(fill=tk.X, pady=4)
        self.result_tv = ttk.Treeview(f, columns=("ip","p"), show="headings")
        self.result_tv.heading("ip", text="IP"); self.result_tv.column("ip", width=180)
        self.result_tv.heading("p", text="Port"); self.result_tv.column("p", width=80)
        self.result_tv.pack(fill=tk.BOTH, expand=True)
        ttk.Button(f, text="Use Selected", command=self._use).pack(pady=4)
    def _detect(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]; s.close(); return ".".join(ip.split(".")[:3])
        except: return "192.168.1"
    def _start(self):
        try:
            subnet = self.subnet_var.get().strip(); port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("Invalid", "Check input", parent=self); return
        self.result_tv.delete(*self.result_tv.get_children()); self.prog.configure(value=0)
        base = ".".join(subnet.split(".")[:3])
        def check(ip):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.3)
                ok = s.connect_ex((ip, port)) == 0; s.close(); return ip if ok else None
            except: return None
        def run():
            done = 0
            with ThreadPoolExecutor(max_workers=64) as ex:
                futures = {ex.submit(check, f"{base}.{i}"): i for i in range(1, 255)}
                for fut in as_completed(futures):
                    done += 1; ip = fut.result()
                    if ip: self.after(0, lambda x=ip: self.result_tv.insert("", tk.END, values=(x, port)))
                    if done % 5 == 0 or done == 254: self.after(0, lambda d=done: self.prog.configure(value=d))
            self.after(0, lambda: self.prog.configure(value=0))
        threading.Thread(target=run, daemon=True).start()
    def _use(self):
        sel = self.result_tv.selection()
        if sel:
            ip = self.result_tv.item(sel[0], "values")[0]
            self.app.host_var.set(ip); self.app.mode_var.set("TCP"); self.app._on_mode(); self.destroy()

class DiscoveryWizard(tk.Toplevel):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.title("Discovery Wizard")
        self.geometry("1100x760")
        self.app = app
        self.scanner = None
        self.results = []
        self._build()
    def _build(self):
        ctl = ttk.LabelFrame(self, text="Step 1: Find Slave IDs", padding=8)
        ctl.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(ctl, text="Slave ID range:").pack(side=tk.LEFT)
        self.start_var = tk.StringVar(value="1")
        ttk.Entry(ctl, textvariable=self.start_var, width=5).pack(side=tk.LEFT, padx=2)
        ttk.Label(ctl, text="to").pack(side=tk.LEFT)
        self.end_var = tk.StringVar(value="10")
        ttk.Entry(ctl, textvariable=self.end_var, width=5).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Scan Slaves", command=self._scan_slaves).pack(side=tk.LEFT, padx=8)
        ttk.Button(ctl, text="Stop", command=self._stop).pack(side=tk.LEFT)
        self.slave_status = tk.StringVar(value="(not scanned)")
        ttk.Label(ctl, textvariable=self.slave_status, foreground="#8cf").pack(side=tk.LEFT, padx=15)
        ctl2 = ttk.LabelFrame(self, text="Step 2: Scan Registers/Coils", padding=8)
        ctl2.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(ctl2, text="Slave ID:").pack(side=tk.LEFT)
        self.slave_var = tk.StringVar(value="1")
        self.slave_cb = ttk.Combobox(ctl2, textvariable=self.slave_var, values=["1"], width=6)
        self.slave_cb.pack(side=tk.LEFT, padx=4)
        ttk.Label(ctl2, text="Start addr:").pack(side=tk.LEFT, padx=(15,2))
        self.addr_start_var = tk.StringVar(value="0")
        ttk.Entry(ctl2, textvariable=self.addr_start_var, width=6).pack(side=tk.LEFT)
        ttk.Label(ctl2, text="Count:").pack(side=tk.LEFT, padx=(15,2))
        self.count_var = tk.StringVar(value="100")
        ttk.Entry(ctl2, textvariable=self.count_var, width=6).pack(side=tk.LEFT)
        ttk.Label(ctl2, text="Type:").pack(side=tk.LEFT, padx=(15,2))
        self.fc_var = tk.StringVar(value="Holding Registers")
        ttk.Combobox(ctl2, textvariable=self.fc_var, values=FC_LIST, width=18, state="readonly").pack(side=tk.LEFT)
        ttk.Button(ctl2, text="Scan", command=self._scan_registers).pack(side=tk.LEFT, padx=8)
        self.prog = ttk.Progressbar(self, mode="indeterminate"); self.prog.pack(fill=tk.X, padx=8, pady=4)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, foreground="#fc4", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12)
        cols = ("slave","fc","addr","raw_hex","value_uint","value_int","value_float","suggest")
        tv_frame = ttk.Frame(self); tv_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.tv = ttk.Treeview(tv_frame, columns=cols, show="headings", height=18)
        heads = {"slave":"Slave","fc":"FC","addr":"Addr","raw_hex":"Raw (hex)","value_uint":"UInt16",
                 "value_int":"Int16","value_float":"Float32","suggest":"Suggested Format"}
        widths = {"slave":50,"fc":130,"addr":60,"raw_hex":130,"value_uint":90,
                  "value_int":90,"value_float":120,"suggest":320}
        for c in cols:
            self.tv.heading(c, text=heads[c])
            self.tv.column(c, width=widths[c], anchor="w" if c == "suggest" else "center")
        self.tv.tag_configure("nonzero", background="#2a3a2a")
        self.tv.tag_configure("coil", background="#3a2a3a")
        sc = ttk.Scrollbar(tv_frame, orient="vertical", command=self.tv.yview)
        self.tv.configure(yscrollcommand=sc.set)
        self.tv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); sc.pack(side=tk.RIGHT, fill=tk.Y)
        self.tv.bind("<Double-1>", lambda e: self._add_selected())
        bot = ttk.Frame(self); bot.pack(fill=tk.X, padx=8, pady=8)
        ttk.Button(bot, text="Add selected to Watch List", command=self._add_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(bot, text="Add all non-zero", command=self._add_all_nonzero).pack(side=tk.LEFT, padx=2)
        ttk.Button(bot, text="Save results (CSV)", command=self._save_csv).pack(side=tk.LEFT, padx=2)
        ttk.Button(bot, text="Close", command=self.destroy).pack(side=tk.RIGHT)
    def _ensure_conn(self):
        if not self.app.conn.connected:
            messagebox.showwarning("Connection", "Connect to PLC first")
            return False
        return True
    def _stop(self):
        if self.scanner: self.scanner.stop()
        self.prog.stop()
        self.status_var.set("Stopped")
    def _scan_slaves(self):
        if not self._ensure_conn(): return
        try:
            start = int(self.start_var.get()); end = int(self.end_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid range"); return
        self.scanner = DiscoveryScanner(self.app.conn, self.app._uid)
        self.prog.start(10); self.status_var.set("Scanning slaves...")
        def progress(sid, ok):
            try:
                self.after(0, lambda s=sid, o=ok: self.status_var.set(f"Checking slave {s}... {'OK' if o else 'no'}"))
            except: pass
        def worker():
            found = self.scanner.scan_slaves(start, end, on_progress=progress)
            self.app.root.after(0, lambda: self._on_slaves_done(found))
        threading.Thread(target=worker, daemon=True).start()
    def _on_slaves_done(self, found):
        self.prog.stop()
        if found:
            self.slave_status.set(f"Active slaves: {found}")
            self.slave_cb["values"] = [str(s) for s in found]
            if found: self.slave_var.set(str(found[0]))
            self.status_var.set(f"{len(found)} device(s) found")
        else:
            self.slave_status.set("No devices responded")
            self.status_var.set("No devices found")
    def _scan_registers(self):
        if not self._ensure_conn(): return
        try:
            slave = int(self.slave_var.get())
            start = int(self.addr_start_var.get())
            count = int(self.count_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid values"); return
        fc = self.fc_var.get()
        self.scanner = DiscoveryScanner(self.app.conn, self.app._uid)
        self.prog.start(10); self.status_var.set(f"Scanning {fc} from {start} to {start+count}...")
        def progress(addr, raw):
            if addr % 5 == 0:
                try:
                    self.after(0, lambda a=addr: self.status_var.set(f"Reading address {a}..."))
                except: pass
        def worker():
            results = self.scanner.scan_registers(slave, fc, start, count, step=1, on_progress=progress)
            self.app.root.after(0, lambda: self._on_regs_done(results))
        threading.Thread(target=worker, daemon=True).start()
    def _on_regs_done(self, results):
        self.prog.stop()
        for r in results: self._render_result(r)
        self.status_var.set(f"{len(results)} addresses read - double-click to add")
    def _render_result(self, r):
        self.results.append(r)
        raw_hex = " ".join(f"{x:04X}" for x in r.raw)
        val_u = r.raw[0] if r.raw else 0
        val_i = val_u if val_u < 32768 else val_u - 65536
        val_f = ""
        if len(r.raw) >= 2:
            try:
                f = decode_value(r.raw[:2], "Float32", "ABCD")
                if isinstance(f, float) and abs(f) < 1e10:
                    val_f = f"{f:.3f}"
            except: pass
        suggest = ""
        if r.fmt_guesses:
            top = r.fmt_guesses[0]
            suggest = f"{top[0]} {top[1]} - {top[3]}"
        tags = ()
        if "Coils" in r.fc or "Discrete" in r.fc: tags = ("coil",)
        elif val_u != 0: tags = ("nonzero",)
        self.tv.insert("", tk.END,
            values=(r.slave_id, r.fc, r.addr, raw_hex, val_u, val_i, val_f, suggest),
            tags=tags)
    def _add_selected(self):
        sel = self.tv.selection()
        if not sel: return
        added = 0
        for iid in sel:
            idx = self.tv.index(iid)
            if idx >= len(self.results): continue
            self._add_result_to_watch(self.results[idx]); added += 1
        self.app.log(f"[+] Added {added} registers from Discovery")
        self.status_var.set(f"{added} registers added")
    def _add_all_nonzero(self):
        added = 0
        for r in self.results:
            if r.raw and r.raw[0] != 0:
                self._add_result_to_watch(r); added += 1
        self.app.log(f"[+] Added {added} non-zero registers")
        self.status_var.set(f"{added} registers added")
    def _add_result_to_watch(self, r):
        best = r.fmt_guesses[0] if r.fmt_guesses else ("UInt16", "ABCD", 0.5, "")
        fmt = best[0]; order = best[1]
        base_name = f"S{r.slave_id}_{r.fc.split()[0]}_{r.addr}"
        existing = {e.name for e in self.app.watch}
        name = base_name
        i = 2
        while name in existing:
            name = f"{base_name}_{i}"
            i += 1
        try:
            e = WatchEntry(addr=r.addr, fc=r.fc, fmt=fmt, order=order,
                           name=name, slave_id=r.slave_id,
                           description=f"Auto-discovered: {best[3]}")
            self.app.watch.append(e)
            self.app._render_watch_row(e)
            self.app._apply_filter()
        except Exception as ex:
            self.app.log(f"[!] Add error: {ex}")
    def _save_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path: return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["Slave","FC","Address","Raw (hex)","UInt16","Int16","Float32","Suggested"])
            for iid in self.tv.get_children(): w.writerow(self.tv.item(iid, "values"))
        self.app.log(f"[+] Discovery results saved: {path}")

class GraphWindow(tk.Toplevel):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.title("Real-Time Graphs"); self.geometry("1000x700")
        self.app = app; self.axes_data = {}; self.paused = False
        self._build(); self._refresh()
    def _build(self):
        ctl = ttk.Frame(self); ctl.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(ctl, text="Pause", command=self._toggle_pause).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Clear", command=self._clear).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Add All", command=self._add_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Remove", command=self._remove).pack(side=tk.LEFT, padx=2)
        self.status_lbl = tk.StringVar(value="Live")
        ttk.Label(ctl, textvariable=self.status_lbl).pack(side=tk.LEFT, padx=10)
        self.select_var = tk.StringVar()
        self.select_cb = ttk.Combobox(ctl, textvariable=self.select_var, width=30)
        self.select_cb.pack(side=tk.RIGHT, padx=2)
        ttk.Button(ctl, text="+ Add", command=self._add).pack(side=tk.RIGHT, padx=4)
        if HAS_MPL:
            self.fig = Figure(figsize=(10, 6), facecolor="#1e1e2e")
            self.canvas = FigureCanvasTkAgg(self.fig, master=self)
            self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        else:
            ttk.Label(self, text="pip install matplotlib", foreground="red").pack(pady=50)
        self._update_select()
    def _update_select(self):
        try:
            self.select_cb["values"] = [e.name for e in self.app.watch]
        except tk.TclError: pass
    def _add(self):
        name = self.select_var.get()
        if name and name not in self.axes_data: self.axes_data[name] = len(self.axes_data) + 1
    def _add_all(self):
        for e in self.app.watch:
            if e.name not in self.axes_data: self.axes_data[e.name] = len(self.axes_data) + 1
    def _remove(self):
        name = self.select_var.get()
        if name in self.axes_data:
            del self.axes_data[name]
            self.axes_data = {n: i+1 for i, n in enumerate(self.axes_data.keys())}
            self._update_select()
    def _clear(self):
        self.axes_data.clear()
        if HAS_MPL: self.fig.clear(); self.canvas.draw()
    def _toggle_pause(self):
        self.paused = not self.paused
        self.status_lbl.set("Paused" if self.paused else "Live")
    def _refresh(self):
        self._update_select()
        if not self.paused and HAS_MPL and self.axes_data:
            self.fig.clear()
            entries = {e.name: e for e in self.app.watch}
            rows = len(self.axes_data)
            for i, name in enumerate(self.axes_data):
                ax = self.fig.add_subplot(rows, 1, i+1)
                ax.set_facecolor("#101418"); ax.tick_params(colors="#888", labelsize=8)
                for sp in ax.spines.values(): sp.set_color("#333")
                e = entries.get(name)
                if e and len(e.history) >= 2:
                    ys = list(e.history); xs = list(range(len(ys)))
                    ax.plot(xs, ys, color="#00d4ff", linewidth=1.5)
                    ax.fill_between(xs, ys, alpha=0.18, color="#00d4ff")
                    for val, color, style in [(e.normal_min,"#f55",":"),(e.normal_max,"#f55",":"),
                                              (e.warn_min,"#fc4","--"),(e.warn_max,"#fc4","--")]:
                        if val is not None: ax.axhline(val, color=color, linestyle=style, alpha=0.55, linewidth=1)
                    ax.set_title(f"{name}  now={ys[-1]:.3f} {e.unit}  {e.health}  {e.trend}", color="#8cf", fontsize=9, loc="left")
                    ax.grid(True, color="#223", linestyle=":", alpha=0.5)
            self.fig.tight_layout(); self.canvas.draw_idle()
        try: self.after(800, self._refresh)
        except: pass

class ReportDialog(tk.Toplevel):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.title("Report"); self.geometry("800x700"); self.app = app; self._build()
    def _build(self):
        ctl = ttk.Frame(self); ctl.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(ctl, text="Save HTML", command=self._save).pack(side=tk.RIGHT, padx=2)
        ttk.Button(ctl, text="Regenerate", command=self._generate).pack(side=tk.RIGHT, padx=2)
        self.text = tk.Text(self, font=("Consolas", 10))
        self.text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self._generate()
    def _generate(self):
        rows = ""
        for e in self.app.watch:
            val = e.last_val if e.last_val is not None else "\u2014"
            health = e.health
            color = "#28a745" if health.startswith("\u2713") else "#ffc107" if health.startswith("\u26a0") else "#dc3545" if health.startswith("\U0001f6a8") else "#6c757d"
            rows += (f"<tr><td>{html.escape(e.name)}</td><td>{e.addr}</td><td>{e.fc}</td><td>{e.fmt}</td>"
                     f"<td style='color:{color};font-weight:bold'>{val} {html.escape(e.unit)}</td>"
                     f"<td style='color:{color}'>{health}</td><td>{e.trend}</td></tr>")
        self.html_content = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Modbus Pro Report</title><style>body{{font-family:Segoe UI;padding:20px}}
table{{border-collapse:collapse;width:100%;background:white}}th,td{{padding:8px;border-bottom:1px solid #ddd}}
th{{background:#0078d4;color:white}}</style></head><body>
<h1>Modbus Pro Report \u2014 {datetime.now():%Y-%m-%d %H:%M}</h1>
<table><thead><tr><th>Name</th><th>Addr</th><th>FC</th><th>Format</th><th>Value</th><th>Health</th><th>Trend</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"""
        self.text.delete("1.0", tk.END)
        for e in self.app.watch:
            self.text.insert(tk.END, f"* {e.name:20s} @{e.addr:<6d} = {e.last_val} {e.unit}  {e.health}\n")
    def _save(self):
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html")])
        if not path: return
        with open(path, "w", encoding="utf-8") as f: f.write(self.html_content)
        messagebox.showinfo("Saved", path, parent=self)

class DataLoggerTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent); self.app = app; self._build()
    def _build(self):
        ctl = ttk.Frame(self); ctl.pack(fill=tk.X, padx=3, pady=3)
        ttk.Button(ctl, text="Refresh", command=self.refresh).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Prune", command=self._prune).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Export", command=self._export).pack(side=tk.LEFT, padx=2)
        ttk.Label(ctl, text="  Rows:").pack(side=tk.LEFT)
        self.limit_var = tk.StringVar(value="200")
        ttk.Entry(ctl, textvariable=self.limit_var, width=6).pack(side=tk.LEFT, padx=2)
        self.status_var = tk.StringVar(value="")
        ttk.Label(ctl, textvariable=self.status_var, foreground="#8cf").pack(side=tk.RIGHT)
        self.nb = ttk.Notebook(self); self.nb.pack(fill=tk.BOTH, expand=True)
        for key, cols in [("Readings", [("ts",140),("name",160),("addr",70),("fc",130),("value",120),("health",120)]),
                          ("Events", [("ts",140),("level",80),("source",160),("message",500)]),
                          ("Writes", [("ts",140),("name",140),("addr",70),("old",100),("new",100),("verified",80),("reason",300)])]:
            f = ttk.Frame(self.nb); self.nb.add(f, text=key)
            tv = ttk.Treeview(f, columns=[c for c,_ in cols], show="headings")
            for c, w in cols: tv.heading(c, text=c.capitalize()); tv.column(c, width=w)
            tv.pack(fill=tk.BOTH, expand=True)
            setattr(self, f"_tv_{key.lower()}", tv)
    def refresh(self):
        if not self.app.logger or not self.app.logger.enabled:
            self.status_var.set("Logger disabled"); return
        try: limit = int(self.limit_var.get())
        except: limit = 200
        try:
            for tv, sql in [(self._tv_readings, f"SELECT ts,name,addr,fc,value,health FROM readings ORDER BY id DESC LIMIT {limit}"),
                            (self._tv_events, f"SELECT ts,level,source,message FROM events ORDER BY id DESC LIMIT {limit}"),
                            (self._tv_writes, f"SELECT ts,name,addr,old,new,verified,reason FROM writes ORDER BY id DESC LIMIT {limit}")]:
                for iid in tv.get_children(): tv.delete(iid)
                for row in self.app.logger.query(sql):
                    if row and isinstance(row[0], str) and row[0] == "ERROR":
                        self.status_var.set(f"DB error: {row[1]}"); continue
                    ts, *rest = row
                    try: ts_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
                    except: ts_str = "\u2014"
                    tv.insert("", 0, values=(ts_str, *rest))
            self.status_var.set(f"Up to {limit} rows")
        except Exception as ex:
            self.status_var.set(f"Refresh error: {ex}")
    def _prune(self):
        if self.app.logger: self.app.logger.prune(); self.refresh()
    def _export(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path: return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["ts","name","addr","fc","value","health"])
            for iid in self._tv_readings.get_children(): w.writerow(self._tv_readings.item(iid, "values"))
        self.status_var.set(f"Exported {path}")

class ManualControlWindow(tk.Toplevel):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.title("Manual Control - Live PLC")
        self.geometry("1000x750")
        self.app = app
        self._controls = {}
        self._user_editing = set()
        self._build()
        self._refresh_loop()
    def _build(self):
        t = THEMES[self.app.theme]
        ctl = ttk.Frame(self); ctl.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(ctl, text="Refresh", command=self._rebuild).pack(side=tk.LEFT, padx=2)
        self.filter_var = tk.StringVar()
        self.filter_var.trace("w", lambda *a: self._rebuild())
        ttk.Label(ctl, text="Filter:").pack(side=tk.LEFT, padx=(10,2))
        ttk.Entry(ctl, textvariable=self.filter_var, width=20).pack(side=tk.LEFT)
        tk.Label(ctl, text="All writes go directly to PLC", fg="#fc4",
                 bg=t["bg"], font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=15)
        self.canvas = tk.Canvas(self, bg=t["bg"], highlightthickness=0)
        sb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.container = tk.Frame(self.canvas, bg=t["bg"])
        self.canvas.create_window((0, 0), window=self.container, anchor="nw")
        self.canvas.configure(yscrollcommand=sb.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.container.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self._rebuild()
    def _rebuild(self):
        for w in self.container.winfo_children(): w.destroy()
        self._controls = {}
        t = THEMES[self.app.theme]
        f = self.filter_var.get().lower().strip()
        entries = [e for e in self.app.watch if not f or f in e.name.lower() or f in (e.description or "").lower()]
        coils = [e for e in entries if e.fc == "Coils"]
        analogs = [e for e in entries if e.fc == "Holding Registers"]
        if coils: self._section("Coils (On/Off)", coils, "coil", t)
        if analogs: self._section("Holding Registers (Analog)", analogs, "analog", t)
        if not coils and not analogs:
            tk.Label(self.container, text="No writable registers.\nUse Scan tab or Add Register.",
                     bg=t["bg"], fg="#888", font=("Segoe UI", 11)).pack(pady=30)
    def _section(self, title, entries, kind, t):
        hdr = tk.Frame(self.container, bg=t["bg"]); hdr.pack(fill=tk.X, padx=10, pady=(10,4))
        tk.Label(hdr, text=title, font=("Segoe UI", 13, "bold"), bg=t["bg"], fg=t["accent"]).pack(anchor="w")
        for e in entries:
            self._make_coil(e, t) if kind == "coil" else self._make_analog(e, t)
    def _make_coil(self, e, t):
        row = tk.Frame(self.container, bg=t["entry"], padx=12, pady=10)
        row.pack(fill=tk.X, padx=10, pady=2)
        left = tk.Frame(row, bg=t["entry"]); left.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(left, text=e.name, bg=t["entry"], fg=t["fg"], font=("Segoe UI", 11, "bold"), anchor="w").pack(anchor="w")
        tk.Label(left, text=f"@{e.addr}  {e.description or ''}", bg=t["entry"], fg="#888", font=("Segoe UI", 8), anchor="w").pack(anchor="w")
        state_lbl = tk.Label(row, text="?", bg=t["entry"], fg="#888", font=("Consolas", 14, "bold"), width=8)
        state_lbl.pack(side=tk.RIGHT, padx=6)
        tk.Button(row, text="OFF", bg="#6a2a2a", fg="white", width=6, font=("Segoe UI", 9, "bold"),
                  command=lambda: self.app._do_write_and_show(e, "0")).pack(side=tk.RIGHT, padx=2)
        tk.Button(row, text="ON", bg="#2a6a2a", fg="white", width=6, font=("Segoe UI", 9, "bold"),
                  command=lambda: self.app._do_write_and_show(e, "1")).pack(side=tk.RIGHT, padx=2)
        self._controls[e.name] = {"lbl": state_lbl, "type": "coil"}
    def _make_analog(self, e, t):
        row = tk.Frame(self.container, bg=t["entry"], padx=12, pady=10)
        row.pack(fill=tk.X, padx=10, pady=2)
        hdr = tk.Frame(row, bg=t["entry"]); hdr.pack(fill=tk.X)
        tk.Label(hdr, text=e.name, bg=t["entry"], fg=t["fg"], font=("Segoe UI", 11, "bold"), anchor="w").pack(side=tk.LEFT)
        tk.Label(hdr, text=f"@{e.addr}  {e.fmt}  {e.description or ''}", bg=t["entry"], fg="#888", font=("Segoe UI", 8), anchor="w").pack(side=tk.LEFT, padx=8)
        ctrl = tk.Frame(row, bg=t["entry"]); ctrl.pack(fill=tk.X, pady=6)
        if e.normal_min is not None and e.normal_max is not None:
            lo = fmt_unscale(float(e.normal_min), e.scale)
            hi = fmt_unscale(float(e.normal_max), e.scale)
        elif e.min_observed is not None and e.max_observed is not None:
            lo = fmt_unscale(float(e.min_observed), e.scale)
            hi = fmt_unscale(float(e.max_observed), e.scale)
        else: lo, hi = 0.0, 1000.0
        if hi <= lo: hi = lo + 100
        val_var = tk.DoubleVar(value=float(e.last_val) if isinstance(e.last_val, (int, float)) else lo)
        slider = ttk.Scale(ctrl, from_=lo, to=hi, variable=val_var, orient=tk.HORIZONTAL, length=350)
        slider.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
        val_lbl = tk.Label(ctrl, text="\u2014", bg=t["entry"], fg=t["accent"], font=("Consolas", 11, "bold"), width=10)
        val_lbl.pack(side=tk.LEFT, padx=6)
        entry_var = tk.StringVar(value=str(e.last_val) if e.last_val is not None else "")
        entry_w = ttk.Entry(ctrl, textvariable=entry_var, width=10)
        entry_w.pack(side=tk.LEFT, padx=2)
        def on_entry_focus(_): self._user_editing.add(e.name)
        def on_entry_blur(_): self._user_editing.discard(e.name)
        entry_w.bind("<FocusIn>", on_entry_focus)
        entry_w.bind("<FocusOut>", on_entry_blur)
        def do_set():
            try: v = float(entry_var.get() or val_var.get())
            except: messagebox.showerror("Invalid", "Enter a number", parent=self); return
            self.app._do_write_and_show(e, str(v))
        tk.Button(ctrl, text="Set", bg=t["accent"], fg="white", width=5, font=("Segoe UI", 9, "bold"),
                  command=do_set).pack(side=tk.LEFT, padx=2)
        def sync_entry(*_): entry_var.set(f"{val_var.get():.3f}")
        slider.configure(command=sync_entry)
        self._controls[e.name] = {"lbl": val_lbl, "var": val_var, "entry": entry_var, "type": "analog"}
    def _refresh_loop(self):
        try:
            for e in self.app.watch:
                ctrl = self._controls.get(e.name)
                if not ctrl: continue
                try:
                    if ctrl["type"] == "coil":
                        state = int(e.last_val) if isinstance(e.last_val, (int, float)) else 0
                        ctrl["lbl"].config(text="ON" if state else "OFF", fg="#4c4" if state else "#888")
                    elif ctrl["type"] == "analog":
                        v = e.last_val
                        ctrl["lbl"].config(text=f"{v:.3f}" if isinstance(v, float) else str(v))
                        if e.name not in self._user_editing and isinstance(v, (int, float)):
                            ctrl["var"].set(float(v)); ctrl["entry"].set(str(v))
                except: pass
            self.after(500, self._refresh_loop)
        except tk.TclError: pass

class MacroEditorWindow(tk.Toplevel):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.title("Macros - Sequence Runner")
        self.geometry("900x650")
        self.app = app
        self._build()
    def _build(self):
        ctl = ttk.Frame(self); ctl.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(ctl, text="New", command=self._new).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Save", command=self._save).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Load", command=self._load).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Run", command=self._run).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Stop", command=self._stop).pack(side=tk.LEFT, padx=2)
        self.name_var = tk.StringVar(value="My Macro")
        ttk.Label(ctl, text="  Name:").pack(side=tk.LEFT, padx=(15,2))
        ttk.Entry(ctl, textvariable=self.name_var, width=25).pack(side=tk.LEFT)
        body = ttk.Frame(self); body.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Label(body, text="Steps (JSON array):",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w")
        ttk.Label(body, text='Example: [{"action":"write","addr":100,"fc":"Holding Registers","fmt":"UInt16","value":1}, {"action":"delay","seconds":1}, {"action":"read","addr":100}]',
                  foreground="#888", font=("Segoe UI", 8), wraplength=880).pack(anchor="w", pady=(0,6))
        self.text = tk.Text(body, height=15, font=("Consolas", 10), bg="#1a1a2a", fg="#c9ffd1", insertbackground="white")
        self.text.pack(fill=tk.BOTH, expand=True)
        self.text.insert("1.0", '[\n  {"action": "write", "addr": 100, "fc": "Holding Registers", "fmt": "UInt16", "value": 1},\n  {"action": "delay", "seconds": 1.0},\n  {"action": "read", "addr": 100}\n]')
        self.log_text = tk.Text(self, height=8, font=("Consolas", 9), bg="#0c0f12", fg="#c9ffd1")
        self.log_text.pack(fill=tk.X, padx=5, pady=5)
    def _new(self):
        self.name_var.set("New Macro")
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", '[\n  {"action": "write", "addr": 0, "value": 0}\n]')
    def _get_macro(self):
        try:
            data = json.loads(self.text.get("1.0", "end-1c").strip() or "[]")
            if not isinstance(data, list): raise ValueError("Must be an array")
            return Macro(self.name_var.get().strip() or "Macro", data)
        except Exception as ex:
            messagebox.showerror("Invalid JSON", str(ex), parent=self); return None
    def _save(self):
        m = self._get_macro()
        if not m: return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")], parent=self)
        if not path: return
        with open(path, "w", encoding="utf-8") as f: json.dump(m.to_dict(), f, indent=2, ensure_ascii=False)
        self._log(f"Saved: {path}")
    def _load(self):
        path = filedialog.askopenfilename(filetypes=[("JSON","*.json")], parent=self)
        if not path: return
        try:
            with open(path, encoding="utf-8") as f: d = json.load(f)
            self.name_var.set(d.get("name", "Macro"))
            self.text.delete("1.0", tk.END)
            self.text.insert("1.0", json.dumps(d.get("steps", []), indent=2, ensure_ascii=False))
            self._log(f"Loaded: {path}")
        except Exception as ex:
            messagebox.showerror("Load failed", str(ex), parent=self)
    def _run(self):
        m = self._get_macro()
        if not m: return
        if not self.app.conn.connected:
            messagebox.showwarning("Disconnected", "Connect to PLC first", parent=self); return
        self._log(f"Running: {m.name}")
        def on_log(msg): self._log(msg)
        def on_done(results):
            ok = sum(1 for r in results if r.get("result", {}).get("verified") or r.get("ok") or r.get("value") is not None)
            self._log(f"Done \u2014 {ok}/{len(results)} steps succeeded")
        self.app.macro_runner.run(m, on_log=on_log, on_done=on_done)
    def _stop(self):
        self.app.macro_runner.stop()
        self._log("Stop requested")
    def _log(self, msg):
        try:
            self.log_text.insert(tk.END, f"[{datetime.now():%H:%M:%S}] {msg}\n")
            self.log_text.see(tk.END)
        except: pass

class RampWindow(tk.Toplevel):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.title("Ramp - Smooth Value Change")
        self.geometry("560x480")
        self.app = app
        self._build()
    def _build(self):
        f = ttk.Frame(self, padding=15); f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text="Ramp a register from A to B over time",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0,10))
        ttk.Label(f, text="Select a Holding Register from your Watch List:",
                  foreground="#888").pack(anchor="w")
        self.entry_var = tk.StringVar()
        self.cb = ttk.Combobox(f, textvariable=self.entry_var, width=40, state="readonly")
        self.cb.pack(fill=tk.X, pady=4)
        self.cb["values"] = [e.name for e in self.app.watch if e.fc == "Holding Registers"]
        grid = ttk.Frame(f); grid.pack(fill=tk.X, pady=10)
        ttk.Label(grid, text="From (raw):").grid(row=0, column=0, sticky="w", pady=4)
        self.from_var = tk.StringVar(value="0")
        ttk.Entry(grid, textvariable=self.from_var, width=15).grid(row=0, column=1, padx=5, sticky="w")
        ttk.Label(grid, text="To (raw):").grid(row=1, column=0, sticky="w", pady=4)
        self.to_var = tk.StringVar(value="100")
        ttk.Entry(grid, textvariable=self.to_var, width=15).grid(row=1, column=1, padx=5, sticky="w")
        ttk.Label(grid, text="Duration (s):").grid(row=2, column=0, sticky="w", pady=4)
        self.dur_var = tk.StringVar(value="10")
        ttk.Entry(grid, textvariable=self.dur_var, width=15).grid(row=2, column=1, padx=5, sticky="w")
        ttk.Label(grid, text="Steps:").grid(row=3, column=0, sticky="w", pady=4)
        self.steps_var = tk.StringVar(value="50")
        ttk.Entry(grid, textvariable=self.steps_var, width=15).grid(row=3, column=1, padx=5, sticky="w")
        btns = ttk.Frame(f); btns.pack(fill=tk.X, pady=15)
        ttk.Button(btns, text="Start Ramp", command=self._start).pack(side=tk.LEFT, padx=2)
        ttk.Button(btns, text="Stop", command=self._stop).pack(side=tk.LEFT, padx=2)
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(f, textvariable=self.status_var, font=("Consolas", 10), foreground="#8cf").pack(anchor="w", pady=8)
    def _start(self):
        name = self.entry_var.get()
        if not name:
            messagebox.showerror("Error", "Select a register", parent=self); return
        entry = next((e for e in self.app.watch if e.name == name and e.fc == "Holding Registers"), None)
        if not entry:
            messagebox.showerror("Error", "Register not found", parent=self); return
        if not self.app.conn.connected:
            messagebox.showerror("Error", "Connect to PLC first", parent=self); return
        try:
            f, t, d, s = float(self.from_var.get()), float(self.to_var.get()), float(self.dur_var.get()), int(self.steps_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid numbers", parent=self); return
        def on_progress(val, result):
            ok = "OK" if result.get("verified") else "X"
            self.status_var.set(f"{ok} step: {val:.3f}")
        def on_done(ok, err):
            self.status_var.set(f"Done" if ok else f"Error: {err}")
        self.app.ramp_runner.run(entry, f, t, d, s, on_progress=on_progress, on_done=on_done)
        self.status_var.set("Ramping...")
    def _stop(self):
        self.app.ramp_runner.stop()
        self.status_var.set("Stopped")

class ModbusProApp:
    def __init__(self, root, startup=None):
        self.root = root
        self.root.title("Modbus Pro v9.4 - Multi-Protocol Control")
        self.root.geometry("1480x940")
        self.conn = ConnectionManager()
        self.watch = []
        self.watch_items = {}
        self.inspector = RequestInspector()
        self.logger = DataLogger()
        self.mqtt = MqttBridge()
        self.poller = PollWorker(self)
        self.write_guard = WriteGuard()
        self.macro_runner = MacroRunner(self)
        self.ramp_runner = RampRunner(self)
        self._log_lines = deque(maxlen=2000)
        self.polling = False
        self.auto_reconnect = True
        self._was_connected = False
        self.health_monitor_id = None
        self._stats_id = None
        self.stats = {"reqs":0,"errs":0,"writes":0,"verified":0,"failed":0,"last_ms":0,"since":time.time()}
        self._stats_lock = threading.Lock()
        self._pending_traffic = queue.Queue(maxsize=2000)
        self.theme = "dark"
        self.scan_results = []
        self.scan_lookup = {}
        self.smart_scanner = None
        self.zeroing_window = None
        self._build_style(); self._build_menu(); self._build_ui()
        self._update_stats(); self._start_health_monitor()
        self._drain_traffic()
        if startup:
            self.mode_var.set(startup["mode"]); self.host_var.set(startup["host"])
            self.port_var.set(str(startup["port"])); self.com_var.set(startup["com"])
            self.baud_var.set(str(startup["baud"])); self.unit_var.set(str(startup["slave"]))
            self.auto_reconnect = startup["auto_reconnect"]
            if startup.get("logger"):
                self.logger.path = startup.get("logger_path", "modbus_pro.db")
                self.logger.retention_days = startup.get("logger_days", 30)
                if self.logger.start(): self.log("[+] SQLite logger -> " + self.logger.path)
            if startup.get("mqtt_enable"):
                ok, msg = self.mqtt.connect(startup["mqtt_host"], startup["mqtt_port"],
                                            startup["mqtt_user"], startup["mqtt_pass"], startup["mqtt_prefix"])
                self.log(f"[+] MQTT: {msg}" if ok else f"[!] MQTT: {msg}")
            self._on_mode()
            self.root.after(150, lambda: self._connect_and_detect(False))
    def open_zeroing_window(self):
        if self.zeroing_window and self.zeroing_window.winfo_exists():
            self.zeroing_window.lift(); self.zeroing_window.focus_force(); return
        self.zeroing_window = ZeroingWindow(self.root, self)
    def _bump(self, key, n=1):
        with self._stats_lock: self.stats[key] = self.stats.get(key, 0) + n
    def _build_style(self):
        style = ttk.Style()
        try: style.theme_use("clam")
        except: pass
        self._apply_theme(self.theme)
    def _apply_theme(self, name):
        t = THEMES[name]; style = ttk.Style()
        style.configure(".", background=t["bg"], foreground=t["fg"])
        style.configure("TFrame", background=t["bg"]); style.configure("TLabel", background=t["bg"], foreground=t["fg"])
        style.configure("TLabelframe", background=t["bg"], foreground=t["fg"])
        style.configure("TLabelframe.Label", background=t["bg"], foreground=t["accent"])
        style.configure("TButton", background=t["entry"], foreground=t["fg"])
        style.configure("TNotebook", background=t["bg"])
        style.configure("TNotebook.Tab", background=t["entry"], foreground=t["fg"], padding=[12,6])
        style.map("TNotebook.Tab", background=[("selected", t["accent"])])
        style.configure("TEntry", fieldbackground=t["entry"], foreground=t["fg"])
        style.configure("TCombobox", fieldbackground=t["entry"], foreground=t["fg"])
        style.configure("Treeview", background=t["tree"], foreground=t["fg"], fieldbackground=t["tree"], rowheight=24, font=("Consolas", 9))
        style.configure("Treeview.Heading", background=t["entry"], foreground=t["fg"], font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", t["sel"])])
        self.root.configure(bg=t["bg"])
        if hasattr(self, "log_text"):
            try: self.log_text.configure(bg=t["log_bg"], fg=t["log_fg"], insertbackground=t["log_fg"])
            except: pass
    def _change_theme(self, name):
        self.theme = name; self._apply_theme(name)
    def _build_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open Project...", command=self.load_project)
        file_menu.add_command(label="Save Project...", command=self.save_project)
        file_menu.add_separator()
        file_menu.add_command(label="Import Excel/CSV...", command=self.import_file)
        file_menu.add_command(label="Export CSV...", command=self.export_csv)
        file_menu.add_command(label="Generate Report...", command=lambda: ReportDialog(self.root, self))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        conn_menu = tk.Menu(menubar, tearoff=0)
        conn_menu.add_command(label="Connect / Disconnect", command=self.toggle_connect)
        conn_menu.add_command(label="Network Scanner...", command=self.open_scanner)
        conn_menu.add_command(label="Auto-Detect Device", command=self.auto_detect)
        conn_menu.add_separator()
        conn_menu.add_command(label="Discovery Wizard...", command=self.open_discovery)
        menubar.add_cascade(label="Connection", menu=conn_menu)
        auto_menu = tk.Menu(menubar, tearoff=0)
        auto_menu.add_command(label="Manual Control...", command=self.open_manual_control)
        auto_menu.add_command(label="Macros...", command=self.open_macro_editor)
        auto_menu.add_command(label="Ramp...", command=self.open_ramp_window)
        auto_menu.add_separator()
        auto_menu.add_command(label="Multi-Protocol Zeroing...", command=self.open_zeroing_window)
        menubar.add_cascade(label="Automation", menu=auto_menu)
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Real-Time Graphs...", command=lambda: GraphWindow(self.root, self))
        menubar.add_cascade(label="Tools", menu=tools_menu)
        safety_menu = tk.Menu(menubar, tearoff=0)
        safety_menu.add_command(label="E-STOP", command=self.emergency_stop)
        safety_menu.add_command(label="Undo Last Write", command=self.undo_last_write)
        safety_menu.add_separator()
        safety_menu.add_command(label="Unlock after E-STOP", command=self.unlock_emergency)
        menubar.add_cascade(label="Safety", menu=safety_menu)
        view_menu = tk.Menu(menubar, tearoff=0)
        for n in THEMES: view_menu.add_command(label=n.capitalize(), command=lambda t=n: self._change_theme(t))
        menubar.add_cascade(label="Theme", menu=view_menu)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)
        self.root.bind("<F5>", lambda e: self.read_watch_all())
        self.root.bind("<F9>", lambda e: self.toggle_polling())
        self.root.bind("<Control-f>", lambda e: self.filter_entry.focus_set() if hasattr(self, "filter_entry") else None)
        self.root.bind("<Control-w>", lambda e: self.write_watch_selected())
        self.root.bind("<Delete>", lambda e: self.remove_watch())
        self.root.bind("<Control-e>", lambda e: self.emergency_stop())
    def _about(self):
        messagebox.showinfo("About",
            "Modbus Pro v9.4 - Multi-Protocol Control\n\n"
            "* Modbus TCP/RTU + Rockwell EtherNet/IP + Unitronics PCOM + Siemens S7\n"
            "* Scan tab: discovers addresses and writability\n"
            "* Write tab: writes and verifies with saved/mismatch/error status\n"
            "* Watch List: poll and monitor registers\n"
            "* Manual Control: ON/OFF coils and analog sliders\n"
            "* Multi-Protocol Zeroing: zero all memory on target devices\n"
            "* Macros, Ramp, Discovery Wizard, Graphs, Reports")
    def _build_ui(self):
        tb = ttk.Frame(self.root, padding=4); tb.pack(fill=tk.X)
        estop = tk.Button(tb, text="E-STOP", bg="#8b0000", fg="white",
                          font=("Segoe UI", 10, "bold"), padx=10,
                          command=self.emergency_stop)
        estop.pack(side=tk.LEFT, padx=2)
        ttk.Separator(tb, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=4)
        ttk.Button(tb, text="Discovery", command=self.open_discovery).pack(side=tk.LEFT, padx=2)
        ttk.Button(tb, text="Connect", command=self.toggle_connect).pack(side=tk.LEFT, padx=2)
        ttk.Button(tb, text="Scan Net", command=self.open_scanner).pack(side=tk.LEFT, padx=2)
        ttk.Separator(tb, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=4)
        ttk.Button(tb, text="Manual", command=self.open_manual_control).pack(side=tk.LEFT, padx=2)
        ttk.Button(tb, text="Macros", command=self.open_macro_editor).pack(side=tk.LEFT, padx=2)
        ttk.Button(tb, text="Ramp", command=self.open_ramp_window).pack(side=tk.LEFT, padx=2)
        ttk.Button(tb, text="Zeroing", command=self.open_zeroing_window).pack(side=tk.LEFT, padx=2)
        ttk.Separator(tb, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=4)
        ttk.Button(tb, text="Open", command=self.load_project).pack(side=tk.LEFT, padx=2)
        ttk.Button(tb, text="Save", command=self.save_project).pack(side=tk.LEFT, padx=2)
        ttk.Button(tb, text="CSV", command=self.export_csv).pack(side=tk.LEFT, padx=2)
        ttk.Button(tb, text="Import", command=self.import_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(tb, text="Poll", command=self.toggle_polling).pack(side=tk.LEFT, padx=2)
        cf = ttk.LabelFrame(self.root, text="Connection", padding=4)
        cf.pack(fill=tk.X, padx=4, pady=2)
        ttk.Label(cf, text="Mode:").grid(row=0, column=0)
        self.mode_var = tk.StringVar(value="TCP")
        cb = ttk.Combobox(cf, textvariable=self.mode_var, values=["TCP","RTU over TCP","RTU"], width=12, state="readonly")
        cb.grid(row=0, column=1, padx=2); cb.bind("<<ComboboxSelected>>", self._on_mode)
        self.tcp_frame = ttk.Frame(cf); self.tcp_frame.grid(row=0, column=2, padx=4)
        ttk.Label(self.tcp_frame, text="Host:").pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(self.tcp_frame, textvariable=self.host_var, width=15).pack(side=tk.LEFT, padx=2)
        ttk.Label(self.tcp_frame, text="Port:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="502")
        ttk.Entry(self.tcp_frame, textvariable=self.port_var, width=6).pack(side=tk.LEFT)
        self.rtu_frame = ttk.Frame(cf); self.rtu_frame.grid(row=0, column=2, padx=4)
        ttk.Label(self.rtu_frame, text="COM:").pack(side=tk.LEFT)
        self.com_var = tk.StringVar(value="COM1")
        ttk.Entry(self.rtu_frame, textvariable=self.com_var, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Label(self.rtu_frame, text="Baud:").pack(side=tk.LEFT)
        self.baud_var = tk.StringVar(value="9600")
        ttk.Combobox(self.rtu_frame, textvariable=self.baud_var,
                     values=["9600","19200","38400","57600","115200"], width=7).pack(side=tk.LEFT, padx=2)
        self.rtu_frame.grid_remove()
        ttk.Label(cf, text="Slave:").grid(row=0, column=3, padx=(10,2))
        self.unit_var = tk.StringVar(value="1")
        ttk.Entry(cf, textvariable=self.unit_var, width=4).grid(row=0, column=4)
        ttk.Label(cf, text="Poll ms:").grid(row=0, column=5, padx=(10,2))
        self.scan_var = tk.StringVar(value="1000")
        ttk.Entry(cf, textvariable=self.scan_var, width=6).grid(row=0, column=6)
        self.status_var = tk.StringVar(value="Disconnected")
        self.status_lbl_widget = ttk.Label(cf, textvariable=self.status_var, foreground="#f55", font=("Segoe UI", 9, "bold"))
        self.status_lbl_widget.grid(row=0, column=7, padx=15)
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)
        self._build_scan_tab()
        self._build_cve_tab()
        self._build_write_tab()
        self._build_watch_tab()
        self._build_traffic_tab()
        self._build_quick_write_tab()
        self._build_raw_tabs()
        self._build_history_tab()
        self._build_logger_tab()
        self._build_log_tab()
        sb = ttk.Frame(self.root); sb.pack(fill=tk.X, side=tk.BOTTOM)
        self.stat_lbl = ttk.Label(sb, text="Ready.", anchor="w", padding=4, background="#101018", foreground="#8cf", font=("Consolas", 9))
        self.stat_lbl.pack(fill=tk.X)

    def _build_cve_tab(self):
        f = ttk.Frame(self.nb); self.nb.add(f, text="CVE Reference")
        top = ttk.Frame(f); top.pack(fill=tk.X, padx=8, pady=8)
        ttk.Label(top, text="Industrial Vulnerability Reference — informational / defensive", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        ttk.Label(f, text="This panel is a reference catalog only. It does not send exploit packets or modify PLCs.", foreground="#d98b24").pack(anchor="w", padx=10)
        cols = ("id", "product", "issue", "defense")
        tree = ttk.Treeview(f, columns=cols, show="headings", height=15)
        tree.heading("id", text="CVE / ID"); tree.heading("product", text="Product / Component")
        tree.heading("issue", text="Reported issue (summary)"); tree.heading("defense", text="Defensive action")
        tree.column("id", width=150, stretch=False); tree.column("product", width=220)
        tree.column("issue", width=390); tree.column("defense", width=390)
        y=ttk.Scrollbar(f, orient="vertical", command=tree.yview); tree.configure(yscrollcommand=y.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8,0), pady=8); y.pack(side=tk.RIGHT, fill=tk.Y, padx=(0,8), pady=8)
        entries = [
            ("CVE-2020-7524", "Schneider Modicon M218", "Malformed IPv4 / out-of-bounds behavior; DoS risk (as described in supplied PoC).", "Patch/firmware review; isolate PLC network; filter unexpected traffic; vendor-approved recovery plan."),
            ("CVE-2024-2403", "Schneider Modicon M221", "Unauthenticated Modbus write risk (as described in supplied PoC).", "Restrict TCP/502 to trusted hosts; segment OT; disable unused access; apply vendor guidance."),
            ("CVE-2025-0327", "Schneider Modicon M340/M580", "Modbus-related controller issue; supplied script includes read/write examples.", "Check exact model/firmware against vendor advisory; network allowlisting; monitor engineering access."),
            ("CVE-2026-9637", "Rockwell Logix / CIP", "Malformed CIP length / denial-of-service claim in supplied PoC.", "Use vendor-approved firmware; limit TCP/44818 and UDP/2222 to authorized OT peers."),
            ("CVE-2024-6242", "Rockwell Trusted Slot", "Trusted Slot bypass claim in supplied PoC.", "Verify advisory applicability and security configuration; restrict programming paths and accounts."),
            ("CVE-2023-3595", "Rockwell ControlLogix 1756-EN2*/EN3*", "CIP crafted-message RCE claim in supplied PoC.", "Inventory module/firmware; apply vendor mitigations; isolate EtherNet/IP and monitor changes."),
            ("CVE-2021-22681", "EtherNet/IP baseline", "ListIdentity request demonstrates unauthenticated device discovery; not itself proof of exploitability.", "Limit discovery traffic across zones; expose device identity only to trusted management systems."),
            ("CVE-2021-27460 / 27466", "Rockwell FactoryTalk AssetCentre", ".NET Remoting deserialization / RCE claim in supplied script.", "Patch AssetCentre; restrict service access; disable unused remoting; review logs and credentials."),
            ("CVE-2026-58115", "Siemens SIMATIC IoT2050 / Node-RED", "Unauthenticated root RCE claim in supplied script.", "Update to vendor-fixed release; require authentication; keep Node-RED off untrusted networks."),
            ("CVE-2019-10936", "Siemens S7-1200/1500", "SZL / information disclosure claim in supplied script.", "Check firmware/advisory; restrict S7 access (TCP/102); minimize exposed diagnostic services."),
            ("CVE-2020-7566", "Schneider Modicon M221", "Weak randomness / brute-force model in supplied script (simplified demonstration).", "Follow vendor password/application protection guidance; segment and monitor programming traffic."),
        ]
        for row in entries: tree.insert("", "end", values=row)
        bottom = ttk.Frame(f); bottom.pack(fill=tk.X, padx=8, pady=(0,8))
        ttk.Button(bottom, text="Copy selected CVE", command=lambda: self._copy_cve_selection(tree)).pack(side=tk.LEFT)
        ttk.Label(bottom, text="Descriptions are based on the uploaded scripts; validate CVE IDs and affected versions with vendor advisories.").pack(side=tk.LEFT, padx=10)

    def _copy_cve_selection(self, tree):
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("CVE Reference", "Select a CVE row first.")
            return
        values = tree.item(selected[0], "values")
        text = " | ".join(str(v) for v in values)
        self.root.clipboard_clear(); self.root.clipboard_append(text)
        messagebox.showinfo("CVE Reference", "Selected CVE entry copied to clipboard.")

    def _build_scan_tab(self):
        f = ttk.Frame(self.nb); self.nb.add(f, text="Scan")
        ctl = ttk.LabelFrame(f, text="Scan parameters", padding=8)
        ctl.pack(fill=tk.X, padx=6, pady=6)
        row = ttk.Frame(ctl); row.pack(fill=tk.X)
        ttk.Label(row, text="Function:").pack(side=tk.LEFT)
        self.scan_fc = tk.StringVar(value="Holding Registers")
        ttk.Combobox(row, textvariable=self.scan_fc, values=FC_LIST,
                     width=18, state="readonly").pack(side=tk.LEFT, padx=4)
        ttk.Label(row, text="Start:").pack(side=tk.LEFT, padx=(12,2))
        self.scan_start = tk.StringVar(value="0")
        ttk.Entry(row, textvariable=self.scan_start, width=6).pack(side=tk.LEFT)
        ttk.Label(row, text="Count:").pack(side=tk.LEFT, padx=(12,2))
        self.scan_count = tk.StringVar(value="50")
        ttk.Entry(row, textvariable=self.scan_count, width=6).pack(side=tk.LEFT)
        ttk.Label(row, text="Slave:").pack(side=tk.LEFT, padx=(12,2))
        self.scan_slave = tk.StringVar(value="1")
        ttk.Entry(row, textvariable=self.scan_slave, width=4).pack(side=tk.LEFT)
        ttk.Label(row, text="Format:").pack(side=tk.LEFT, padx=(12,2))
        self.scan_fmt = tk.StringVar(value="UInt16")
        ttk.Combobox(row, textvariable=self.scan_fmt,
                     values=["UInt16","Int16","Float32","Int32"],
                     width=8, state="readonly").pack(side=tk.LEFT)
        row2 = ttk.Frame(ctl); row2.pack(fill=tk.X, pady=(8,0))
        self.test_writable_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="Test if writable",
                        variable=self.test_writable_var).pack(side=tk.LEFT)
        ttk.Button(row2, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=8)
        ttk.Button(row2, text="Stop", command=self.stop_scan).pack(side=tk.LEFT)
        self.scan_prog = ttk.Progressbar(row2, length=200, mode="determinate")
        self.scan_prog.pack(side=tk.RIGHT, padx=4)
        self.scan_status = tk.StringVar(value="")
        ttk.Label(row2, textvariable=self.scan_status, foreground="#8cf").pack(side=tk.RIGHT, padx=4)
        tv_frame = ttk.Frame(f); tv_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        cols = ("addr","value","exists","writable","error")
        self.scan_tv = ttk.Treeview(tv_frame, columns=cols, show="headings", height=18)
        heads = {"addr":"Address","value":"Value","exists":"Exists",
                 "writable":"Writable","error":"Error / Info"}
        widths = {"addr":70,"value":130,"exists":80,"writable":90,"error":550}
        for c in cols:
            self.scan_tv.heading(c, text=heads[c])
            self.scan_tv.column(c, width=widths[c],
                                anchor="w" if c in ("error","value") else "center")
        self.scan_tv.tag_configure("ok", foreground="#4c4")
        self.scan_tv.tag_configure("yes", foreground="#4c4")
        self.scan_tv.tag_configure("no", foreground="#888")
        self.scan_tv.tag_configure("err", foreground="#f55")
        self.scan_tv.tag_configure("warn", foreground="#fc4")
        self.scan_tv.tag_configure("active", background="#1a2a1a")
        sc = ttk.Scrollbar(tv_frame, orient="vertical", command=self.scan_tv.yview)
        self.scan_tv.configure(yscrollcommand=sc.set)
        self.scan_tv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sc.pack(side=tk.RIGHT, fill=tk.Y)
        self.scan_tv.bind("<Double-1>", self._scan_double_click)
        bot = ttk.Frame(f); bot.pack(fill=tk.X, padx=6, pady=6)
        ttk.Button(bot, text="Write to selected address...",
                   command=self._scan_write_selected).pack(side=tk.LEFT)
        ttk.Button(bot, text="Add to Watch List",
                   command=self._scan_add_to_watch).pack(side=tk.LEFT, padx=6)
        ttk.Button(bot, text="Export scan (CSV)",
                   command=self._export_scan).pack(side=tk.LEFT, padx=6)

    def start_scan(self):
        if not self.conn.connected:
            messagebox.showwarning("Not connected", "Connect to a PLC first.")
            return
        try:
            start = int(self.scan_start.get())
            count = int(self.scan_count.get())
            slave = int(self.scan_slave.get())
        except ValueError:
            messagebox.showerror("Invalid", "Start, Count and Slave must be integers")
            return
        fc = self.scan_fc.get()
        test_wr = self.test_writable_var.get()
        fmt = self.scan_fmt.get()
        for iid in self.scan_tv.get_children(): self.scan_tv.delete(iid)
        self.scan_results.clear()
        self.scan_lookup.clear()
        self.scan_prog.configure(value=0, maximum=count)
        self.scan_status.set(f"Scanning {fc} {start}..{start+count-1}...")
        self.smart_scanner = SmartScanner(self.conn, self._uid)
        scanner = self.smart_scanner
        def on_result(st):
            self.root.after(0, lambda: self._add_scan_row(st))
        def on_progress(done, total):
            self.root.after(0, lambda: self.scan_prog.configure(value=done))
        def worker():
            scanner.scan_range(fc, start, count, slave, test_wr, on_result, on_progress, fmt)
            self.root.after(0, self._scan_done)
        threading.Thread(target=worker, daemon=True).start()
        self.log(f"Scan started: {fc} {start}..{start+count-1} slave={slave}")

    def stop_scan(self):
        if self.smart_scanner: self.smart_scanner.stop()

    def _add_scan_row(self, st):
        self.scan_results.append(st)
        self.scan_lookup[st.addr] = st
        exists = "Yes" if st.exists else "No"
        value = str(st.value) if st.exists and st.value is not None else "\u2014"
        if st.writable is True: writable = "Yes"
        elif st.writable is False: writable = "No"
        else: writable = "\u2014"
        err = st.error or st.writable_note or ""
        tags = ()
        if not st.exists:
            tags = ("err",)
        else:
            tags = ("active",)
            if st.writable is True: tags += ("yes",)
            elif st.writable is False: tags += ("no",)
            if st.writable_note: tags += ("warn",)
        self.scan_tv.insert("", tk.END, values=(st.addr, value, exists, writable, err), tags=tags)

    def _scan_done(self):
        active = sum(1 for s in self.scan_results if s.exists)
        writable = sum(1 for s in self.scan_results if s.writable is True)
        self.scan_status.set(f"Complete. Active: {active}, Writable: {writable}")
        self.log(f"Scan done. Active: {active}, Writable: {writable}")

    def _scan_double_click(self, event):
        item = self.scan_tv.identify_row(event.y)
        if not item: return
        self.scan_tv.selection_set(item)
        self._scan_write_selected()

    def _scan_write_selected(self):
        sel = self.scan_tv.selection()
        if not sel:
            messagebox.showinfo("Select", "Select a row first.")
            return
        vals = self.scan_tv.item(sel[0], "values")
        addr = int(vals[0])
        st = self.scan_lookup.get(addr)
        if not st: return
        if st.fc not in WRITABLE:
            messagebox.showinfo("Read-only", f"{st.fc} is not writable.")
        self.wr_fc.set(st.fc if st.fc in ("Holding Registers","Coils") else "Holding Registers")
        self.wr_addr.set(str(addr))
        self.wr_slave.set(str(st.slave_id))
        self.wr_fmt.set(st.fmt if st.fmt in FORMATS else "UInt16")
        self.wr_val.set(str(st.value) if st.value is not None else "")
        self.nb.select(1)

    def _scan_add_to_watch(self):
        sel = self.scan_tv.selection()
        if not sel: return
        added = 0
        for iid in sel:
            vals = self.scan_tv.item(iid, "values")
            addr = int(vals[0])
            st = self.scan_lookup.get(addr)
            if not st or not st.exists: continue
            try:
                e = WatchEntry(addr=st.addr, fc=st.fc, fmt=st.fmt, order="ABCD",
                               name=f"S{st.slave_id}_{st.fc.split()[0]}_{st.addr}",
                               slave_id=st.slave_id)
                self.watch.append(e)
                self._render_watch_row(e)
                added += 1
            except: pass
        self._apply_filter()
        self.log(f"Added {added} from scan to Watch List")

    def _export_scan(self):
        if not self.scan_results:
            messagebox.showinfo("Empty", "Nothing to export. Run a scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path: return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["Address","Value","Exists","Writable","Error","FC","Slave"])
            for s in self.scan_results:
                w.writerow([s.addr, s.value, "Yes" if s.exists else "No",
                            "Yes" if s.writable is True else ("No" if s.writable is False else "\u2014"),
                            s.error or s.writable_note or "", s.fc, s.slave_id])
        self.log(f"Scan exported: {path}")

    def _build_write_tab(self):
        f = ttk.Frame(self.nb); self.nb.add(f, text="Write")
        top = ttk.LabelFrame(f, text="Write to a register", padding=10)
        top.pack(fill=tk.X, padx=6, pady=6)
        grid = ttk.Frame(top); grid.pack(fill=tk.X)
        ttk.Label(grid, text="Function:").grid(row=0, column=0, sticky="w", padx=(0,6), pady=4)
        self.wr_fc = tk.StringVar(value="Holding Registers")
        ttk.Combobox(grid, textvariable=self.wr_fc,
                     values=["Holding Registers","Coils"],
                     width=18, state="readonly").grid(row=0, column=1, sticky="w", pady=4)
        ttk.Label(grid, text="Address:").grid(row=0, column=2, sticky="w", padx=(20,6), pady=4)
        self.wr_addr = tk.StringVar(value="0")
        ttk.Entry(grid, textvariable=self.wr_addr, width=8).grid(row=0, column=3, sticky="w", pady=4)
        ttk.Label(grid, text="Slave:").grid(row=0, column=4, sticky="w", padx=(20,6), pady=4)
        self.wr_slave = tk.StringVar(value="1")
        ttk.Entry(grid, textvariable=self.wr_slave, width=4).grid(row=0, column=5, sticky="w", pady=4)
        ttk.Label(grid, text="Format:").grid(row=1, column=0, sticky="w", padx=(0,6), pady=4)
        self.wr_fmt = tk.StringVar(value="UInt16")
        ttk.Combobox(grid, textvariable=self.wr_fmt,
                     values=FORMATS, width=18, state="readonly").grid(row=1, column=1, sticky="w", pady=4)
        ttk.Label(grid, text="New value:").grid(row=1, column=2, sticky="w", padx=(20,6), pady=4)
        self.wr_val = tk.StringVar()
        ttk.Entry(grid, textvariable=self.wr_val, width=22,
                  font=("Consolas", 11)).grid(row=1, column=3, columnspan=2, sticky="w", pady=4)
        ttk.Button(grid, text="Write & Verify", command=self.do_write_direct).grid(
            row=1, column=5, padx=(6,0), pady=4)
        self.wr_result_frame = ttk.LabelFrame(f, text="Result", padding=10)
        self.wr_result_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.wr_result_text = tk.Text(self.wr_result_frame, font=("Consolas", 10),
                                       wrap="word", height=15, bg="#0f1418", fg="#eee",
                                       insertbackground="white")
        self.wr_result_text.pack(fill=tk.BOTH, expand=True)
        self.wr_result_text.insert("1.0", "Write results will appear here.")
        self.wr_result_text.configure(state="disabled")

    def do_write_direct(self):
        if not self.conn.connected:
            messagebox.showwarning("Not connected", "Connect to a PLC first.")
            return
        fc = self.wr_fc.get()
        if fc not in WRITABLE:
            self._show_write_result_panel("ERROR", "Not writable.")
            return
        try:
            addr = int(self.wr_addr.get())
            slave = int(self.wr_slave.get())
        except ValueError:
            messagebox.showerror("Invalid", "Address and Slave must be integers")
            return
        new_val_str = self.wr_val.get().strip()
        if not new_val_str:
            messagebox.showerror("Invalid", "Enter a value to write")
            return
        fmt = self.wr_fmt.get()
        try:
            if fc == "Coils":
                v = int(float(new_val_str))
                encoded = [1 if v else 0]
                write_bool = bool(v)
            else:
                encoded = encode_value(new_val_str, fmt)
                write_bool = None
        except Exception as ex:
            self._show_write_result_panel("ERROR", f"Cannot encode '{new_val_str}': {ex}")
            return
        self._show_write_result_panel("PENDING", f"Writing {addr} = {new_val_str} ...")
        def worker():
            result = self._write_and_verify(fc, addr, encoded, slave, fmt, new_val_str, write_bool)
            self.root.after(0, lambda: self._apply_write_result_panel(result))
        threading.Thread(target=worker, daemon=True).start()

    def _write_and_verify(self, fc, addr, encoded, slave, fmt, original_str, write_bool):
        old_raw = None
        try:
            if fc == "Coils":
                rr = self.conn.call(self.conn.client.read_coils, addr, count=1, uid=slave)
                if rr and not rr.isError():
                    old_raw = [1 if b else 0 for b in rr.bits[:1]]
            else:
                n = reg_count(fmt)
                rr = self.conn.call(self.conn.client.read_holding_registers, addr, count=n, uid=slave)
                if rr and not rr.isError():
                    old_raw = list(rr.registers)
        except: pass
        try:
            if fc == "Coils":
                r = self.conn.call(self.conn.client.write_coil, addr, write_bool, uid=slave)
            else:
                if len(encoded) == 1:
                    r = self.conn.call(self.conn.client.write_register, addr, encoded[0], uid=slave)
                else:
                    r = self.conn.call(self.conn.client.write_registers, addr, encoded, uid=slave)
            self._bump("writes")
            if r is None:
                self._bump("failed")
                return WriteResult(status="error", addr=addr, fc=fc,
                                   message="No response from device.", expected=encoded,
                                   old_raw=old_raw, fmt=fmt)
            if hasattr(r, "isError") and r.isError():
                self._bump("failed")
                return WriteResult(status="error", addr=addr, fc=fc,
                                   message=explain_exception(r), expected=encoded,
                                   old_raw=old_raw, fmt=fmt)
            time.sleep(0.12)
            n = reg_count(fmt) if fc == "Holding Registers" else 1
            if fc == "Coils":
                rb = self.conn.call(self.conn.client.read_coils, addr, count=n, uid=slave)
            else:
                rb = self.conn.call(self.conn.client.read_holding_registers, addr, count=n, uid=slave)
            if rb is None:
                return WriteResult(status="unverified", addr=addr, fc=fc,
                                   message="Write sent, read-back failed.", expected=encoded,
                                   old_raw=old_raw, fmt=fmt)
            if hasattr(rb, "isError") and rb.isError():
                return WriteResult(status="unverified", addr=addr, fc=fc,
                                   message=f"Read-back error: {explain_exception(rb)}", expected=encoded,
                                   old_raw=old_raw, fmt=fmt)
            if fc == "Coils":
                actual = [1 if b else 0 for b in rb.bits[:n]]
            else:
                actual = list(rb.registers)
            if actual[:len(encoded)] == encoded:
                self._bump("verified")
                return WriteResult(status="saved", addr=addr, fc=fc,
                                   message="Device confirmed the new value.",
                                   expected=encoded, actual=actual,
                                   old_raw=old_raw, fmt=fmt)
            self._bump("failed")
            return WriteResult(status="mismatch", addr=addr, fc=fc,
                               message="Device did not keep the value.",
                               expected=encoded, actual=actual,
                               old_raw=old_raw, fmt=fmt)
        except Exception as ex:
            self._bump("failed")
            return WriteResult(status="error", addr=addr, fc=fc, message=f"Exception: {ex}",
                               old_raw=old_raw, fmt=fmt)

    def _show_write_result_panel(self, kind, text):
        self.wr_result_text.configure(state="normal")
        self.wr_result_text.delete("1.0", tk.END)
        self.wr_result_text.insert(tk.END, f"{kind}\n", kind)
        self.wr_result_text.insert(tk.END, text)
        self.wr_result_text.tag_configure("SAVED", foreground="#4c4", font=("Consolas", 14, "bold"))
        self.wr_result_text.tag_configure("MISMATCH", foreground="#fc4", font=("Consolas", 14, "bold"))
        self.wr_result_text.tag_configure("ERROR", foreground="#f55", font=("Consolas", 14, "bold"))
        self.wr_result_text.tag_configure("UNVERIFIED", foreground="#fc4", font=("Consolas", 14, "bold"))
        self.wr_result_text.tag_configure("PENDING", foreground="#8cf", font=("Consolas", 12, "bold"))
        self.wr_result_text.configure(state="disabled")

    def _apply_write_result_panel(self, wr):
        if wr.status == "saved" and wr.old_raw is not None:
            try:
                e = WatchEntry(wr.addr, wr.fc, wr.fmt, wr.order, f"Write_{wr.addr}")
                old_val = decode_value(wr.old_raw, wr.fmt, wr.order)
                self.write_guard.push_undo(e, old_val)
            except: pass
        lines = [f"Address:  {wr.addr}  ({wr.fc})"]
        if wr.expected is not None:
            lines.append(f"Sent:     {' '.join(f'{r:04X}' for r in wr.expected)}")
        if wr.actual is not None:
            lines.append(f"Readback: {' '.join(f'{r:04X}' for r in wr.actual)}")
        lines.append("")
        lines.append(wr.message)
        header = {"saved":"SAVED", "mismatch":"MISMATCH",
                  "unverified":"UNVERIFIED", "error":"ERROR"}.get(wr.status, wr.status.upper())
        self._show_write_result_panel(header, "\n".join(lines))
        if wr.status == "saved":
            self.log(f"WRITE SAVED: {wr.addr} = {wr.expected}")
        elif wr.status == "mismatch":
            self.log(f"WRITE MISMATCH: {wr.addr}")
        else:
            self.log(f"WRITE ERROR: {wr.addr} \u2014 {wr.message}")

    def _build_watch_tab(self):
        f = ttk.Frame(self.nb); self.nb.add(f, text="Watch List")
        ctl = ttk.Frame(f); ctl.pack(fill=tk.X, padx=3, pady=3)
        ttk.Button(ctl, text="Discovery", command=self.open_discovery).pack(side=tk.LEFT, padx=1)
        ttk.Button(ctl, text="Add", command=self.add_watch).pack(side=tk.LEFT, padx=1)
        ttk.Button(ctl, text="Edit", command=self.edit_watch).pack(side=tk.LEFT, padx=1)
        ttk.Button(ctl, text="Remove", command=self.remove_watch).pack(side=tk.LEFT, padx=1)
        ttk.Button(ctl, text="Read All", command=self.read_watch_all).pack(side=tk.LEFT, padx=1)
        ttk.Button(ctl, text="Write", command=self.write_watch_selected).pack(side=tk.LEFT, padx=1)
        ttk.Button(ctl, text="Bits", command=self.edit_bits).pack(side=tk.LEFT, padx=1)
        ttk.Label(ctl, text="  Filter:").pack(side=tk.LEFT, padx=(10,0))
        self.filter_var = tk.StringVar(); self.filter_var.trace("w", lambda *a: self._apply_filter())
        self.filter_entry = ttk.Entry(ctl, textvariable=self.filter_var, width=20)
        self.filter_entry.pack(side=tk.LEFT, padx=2)
        paned = ttk.PanedWindow(f, orient=tk.VERTICAL); paned.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
        tv_frame = ttk.Frame(paned); paned.add(tv_frame, weight=3)
        cols = ("name","desc","fc","addr","slave","value","scaled","unit","health","trend","age")
        self.watch_tv = ttk.Treeview(tv_frame, columns=cols, show="headings", height=14)
        widths = {"name":140,"desc":220,"fc":110,"addr":60,"slave":50,"value":110,"scaled":110,"unit":50,"health":130,"trend":110,"age":60}
        heads = {"name":"Name","desc":"Description","fc":"Function","addr":"Addr","slave":"Slv",
                 "value":"Value","scaled":"Scaled","unit":"Unit","health":"Health","trend":"Trend","age":"Age"}
        for c in cols:
            self.watch_tv.heading(c, text=heads[c])
            self.watch_tv.column(c, width=widths[c], anchor="w" if c in ("name","desc") else "center")
        sc = ttk.Scrollbar(tv_frame, orient="vertical", command=self.watch_tv.yview)
        self.watch_tv.configure(yscrollcommand=sc.set)
        self.watch_tv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); sc.pack(side=tk.RIGHT, fill=tk.Y)
        self.watch_tv.tag_configure("changed",  background="#5a3030")
        self.watch_tv.tag_configure("fresh",    background="#2a4a30")
        self.watch_tv.tag_configure("critical", background="#7a1a1a")
        self.watch_tv.tag_configure("warning",  background="#7a5a1a")
        self.watch_tv.bind("<<TreeviewSelect>>", self._on_watch_select)
        self.watch_tv.bind("<Double-1>", lambda e: self.write_watch_selected())
        self.watch_tv.bind("<Button-3>", self._watch_context_menu)
        self.details = RegisterDetailsPanel(paned, self)
        paned.add(self.details, weight=1)

    def _build_traffic_tab(self):
        f = ttk.Frame(self.nb); self.nb.add(f, text="Traffic")
        self.traffic_view = TrafficInspector(f, self)
        self.traffic_view.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

    def _build_quick_write_tab(self):
        f = ttk.Frame(self.nb); self.nb.add(f, text="Quick Write")
        ttk.Label(f, text="Write to any address directly on the PLC.",
                  foreground="#888").pack(anchor="w", padx=10, pady=(10,5))
        grid = ttk.Frame(f); grid.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(grid, text="Address:").grid(row=0, column=0, sticky="w", pady=5)
        self.qw_addr = tk.StringVar(value="0")
        ttk.Entry(grid, textvariable=self.qw_addr, width=15).grid(row=0, column=1, padx=5, sticky="w")
        ttk.Label(grid, text="Function:").grid(row=0, column=2, sticky="w", padx=(20,0))
        self.qw_fc = tk.StringVar(value="Holding Registers")
        ttk.Combobox(grid, textvariable=self.qw_fc, values=list(WRITABLE), width=18, state="readonly").grid(row=0, column=3, padx=5, sticky="w")
        ttk.Label(grid, text="Format:").grid(row=1, column=0, sticky="w", pady=5)
        self.qw_fmt = tk.StringVar(value="UInt16")
        ttk.Combobox(grid, textvariable=self.qw_fmt, values=FORMATS, width=15, state="readonly").grid(row=1, column=1, padx=5, sticky="w")
        ttk.Label(grid, text="Byte Order:").grid(row=1, column=2, sticky="w", padx=(20,0))
        self.qw_order = tk.StringVar(value="ABCD")
        ttk.Combobox(grid, textvariable=self.qw_order, values=BYTE_ORDERS, width=18, state="readonly").grid(row=1, column=3, padx=5, sticky="w")
        ttk.Label(grid, text="New Value:").grid(row=2, column=0, sticky="w", pady=10)
        self.qw_val = tk.StringVar()
        ent = ttk.Entry(grid, textvariable=self.qw_val, width=30, font=("Consolas", 11))
        ent.grid(row=2, column=1, columnspan=2, padx=5, sticky="w")
        ent.bind("<Return>", lambda e: self._quick_write())
        presets = ttk.Frame(f); presets.pack(fill=tk.X, padx=10)
        ttk.Label(presets, text="Presets:").pack(side=tk.LEFT)
        for p in PRESETS:
            ttk.Button(presets, text=str(p), width=6, command=lambda v=p: self.qw_val.set(str(v))).pack(side=tk.LEFT, padx=1)
        btnf = ttk.Frame(f); btnf.pack(pady=15)
        ttk.Button(btnf, text="Read Current", command=self._quick_read).pack(side=tk.LEFT, padx=5)
        ttk.Button(btnf, text="Write to PLC", command=self._quick_write).pack(side=tk.LEFT, padx=5)
        cur = ttk.LabelFrame(f, text="Current Value", padding=8); cur.pack(fill=tk.X, padx=10, pady=10)
        self.qw_current = tk.StringVar(value="\u2014")
        ttk.Label(cur, textvariable=self.qw_current, font=("Consolas", 12, "bold")).pack(anchor="w")
        self.qw_result_frame = ttk.LabelFrame(f, text="Last Write Result", padding=8)
        self.qw_result_frame.pack(fill=tk.X, padx=10, pady=5)
        self.qw_result_label = ttk.Label(self.qw_result_frame, text="\u2014", font=("Segoe UI", 10))
        self.qw_result_label.pack(anchor="w")

    def _build_raw_tabs(self):
        self.raw_tabs = {}
        for key in FC_LIST:
            f = ttk.Frame(self.nb); self.nb.add(f, text=key)
            ctl = ttk.Frame(f); ctl.pack(fill=tk.X, padx=3, pady=3)
            ttk.Label(ctl, text="Start:").pack(side=tk.LEFT)
            sv = tk.StringVar(value="0"); ttk.Entry(ctl, textvariable=sv, width=8).pack(side=tk.LEFT, padx=2)
            ttk.Label(ctl, text="Count:").pack(side=tk.LEFT)
            cv = tk.StringVar(value="20"); ttk.Entry(ctl, textvariable=cv, width=8).pack(side=tk.LEFT, padx=2)
            ttk.Label(ctl, text="Format:").pack(side=tk.LEFT, padx=(10,2))
            fv = tk.StringVar(value="UInt16")
            ttk.Combobox(ctl, textvariable=fv, values=FORMATS, width=8, state="readonly").pack(side=tk.LEFT)
            ttk.Label(ctl, text="Order:").pack(side=tk.LEFT, padx=(10,2))
            ov = tk.StringVar(value="ABCD")
            ttk.Combobox(ctl, textvariable=ov, values=BYTE_ORDERS, width=10, state="readonly").pack(side=tk.LEFT)
            ttk.Button(ctl, text="Read", command=lambda k=key: self.do_raw_read(k)).pack(side=tk.LEFT, padx=6)
            wb = ttk.Button(ctl, text="Write", command=lambda k=key: self.do_raw_write(k))
            wb.pack(side=tk.LEFT, padx=2)
            if key not in WRITABLE: wb.configure(state="disabled")
            tv = ttk.Treeview(f, columns=("addr","raw","value","meaning"), show="headings", height=15)
            for c, w in [("addr",90),("raw",180),("value",260),("meaning",260)]:
                tv.heading(c, text=c.capitalize()); tv.column(c, width=w, anchor="center" if c == "addr" else "w")
            tv.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
            tv.bind("<Double-1>", lambda e, k=key: self.do_raw_write(k))
            self.raw_tabs[key] = {"start":sv,"count":cv,"fmt":fv,"order":ov,"tv":tv}

    def _build_history_tab(self):
        f = ttk.Frame(self.nb); self.nb.add(f, text="Write History")
        ctl = ttk.Frame(f); ctl.pack(fill=tk.X, padx=3, pady=3)
        ttk.Button(ctl, text="Clear", command=self._clear_history).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Export", command=self._export_history).pack(side=tk.LEFT, padx=2)
        ttk.Button(ctl, text="Undo Last", command=self.undo_last_write).pack(side=tk.LEFT, padx=2)
        cols = ("time","name","addr","fc","old","new","status")
        self.history_tv = ttk.Treeview(f, columns=cols, show="headings", height=20)
        for c, w in [("time",80),("name",180),("addr",80),("fc",150),("old",120),("new",120),("status",90)]:
            self.history_tv.heading(c, text=c.capitalize()); self.history_tv.column(c, width=w, anchor="center")
        self.history_tv.tag_configure("ok", background="#1a5a2a")
        self.history_tv.tag_configure("fail", background="#7a2a2a")
        self.history_tv.tag_configure("warn", background="#7a6a20")
        self.history_tv.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

    def _build_logger_tab(self):
        f = ttk.Frame(self.nb); self.nb.add(f, text="Logger")
        self.logger_tab = DataLoggerTab(f, self)
        self.logger_tab.pack(fill=tk.BOTH, expand=True)

    def _build_log_tab(self):
        t = THEMES[self.theme]
        f = ttk.Frame(self.nb); self.nb.add(f, text="Log")
        ctl = ttk.Frame(f); ctl.pack(fill=tk.X, padx=3, pady=3)
        ttk.Button(ctl, text="Clear", command=lambda: self.log_text.delete("1.0", tk.END)).pack(side=tk.LEFT, padx=2)
        self.log_text = tk.Text(f, wrap="word", font=("Consolas", 9), bg=t["log_bg"], fg=t["log_fg"], insertbackground=t["log_fg"])
        sc = ttk.Scrollbar(f, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sc.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3, pady=3)
        sc.pack(side=tk.RIGHT, fill=tk.Y, pady=3)
        for line in self._log_lines: self.log_text.insert(tk.END, line)
        self.log_text.see(tk.END)

    def _on_mode(self, event=None):
        if self.conn.connected:
            self.disconnect(); self.log("[!] Mode changed - disconnected")
        if self.mode_var.get() == "RTU": self.tcp_frame.grid_remove(); self.rtu_frame.grid()
        else: self.rtu_frame.grid_remove(); self.tcp_frame.grid()
    def toggle_connect(self):
        if self.conn.connected: self.disconnect()
        else: self.connect()
    def _connect_and_detect(self, detect):
        self.connect()
        if detect and self.conn.connected: self.auto_detect()
    def connect(self):
        if not HAS_PYM:
            messagebox.showerror("pymodbus", "pip install 'pymodbus>=3.0'"); return
        try:
            port = int(self.port_var.get()); baud = int(self.baud_var.get())
        except ValueError:
            messagebox.showerror("Invalid", "Port/Baud must be numeric"); return
        ok = self.conn.connect(self.mode_var.get(), host=self.host_var.get().strip(),
                               port=port, com=self.com_var.get().strip(), baud=baud)
        if ok:
            self._was_connected = True
            self.write_guard.set_emergency_lock(False)
            self.status_var.set(f"Connected ({self.mode_var.get()})")
            self.status_lbl_widget.configure(foreground="#4c4")
            self.log(f"[+] Connected -> {self.mode_var.get()} {self.host_var.get()}:{self.port_var.get()}")
        else:
            messagebox.showerror("Connect", "Failed to open connection.")
    def disconnect(self):
        self.toggle_polling(force_stop=True); self.stop_scan()
        self.conn.disconnect()
        self.status_var.set("Disconnected")
        self.status_lbl_widget.configure(foreground="#f55")
        self.log("[-] Disconnected")
    def emergency_stop(self):
        self.toggle_polling(force_stop=True); self.stop_scan()
        self.macro_runner.stop(); self.ramp_runner.stop()
        self.write_guard.set_emergency_lock(True)
        self.conn.disconnect()
        self._was_connected = False
        self.status_var.set("E-STOP - LOCKED")
        self.status_lbl_widget.configure(foreground="#f00")
        self.log("[E-STOP] Everything stopped.")
    def unlock_emergency(self):
        self.write_guard.set_emergency_lock(False)
        self.status_var.set("Unlocked (disconnected)")
        self.status_lbl_widget.configure(foreground="#888")
        self.log("[Unlock] Emergency lock cleared")
    def undo_last_write(self):
        prev = self.write_guard.peek_undo()
        if not prev:
            messagebox.showinfo("Undo", "Nothing to undo"); return
        entry_dict, prev_value = prev
        try: e = WatchEntry.from_dict(entry_dict)
        except Exception as ex:
            messagebox.showerror("Undo", f"Invalid: {ex}"); return
        if not self.conn.connected:
            messagebox.showwarning("Undo", "Connect to PLC first"); return
        self.write_guard.pop_undo()
        self.log(f"[Undo] {e.name} = {prev_value}")
        self._do_write_and_show(e, str(prev_value))
    def _uid(self):
        try: return int(self.unit_var.get().strip())
        except: return 1

    def _call(self, method, *a, uid=None, **kw):
        uid = uid if uid is not None else self._uid()
        fn_name = getattr(method, "__name__", "unknown")
        fc_num, fc_desc = FC_NAMES.get(fn_name, (None, fn_name))
        t0 = time.perf_counter()
        result = self.conn.call(method, *a, uid=uid, **kw)
        dt = int((time.perf_counter() - t0) * 1000)
        addr = count = values = None
        if fn_name in ("write_register","write_coil"):
            addr = a[0] if len(a) > 0 else kw.get("address")
            values = a[1] if len(a) > 1 else kw.get("value")
        elif fn_name in ("write_registers","write_coils"):
            addr = a[0] if len(a) > 0 else kw.get("address")
            values = a[1] if len(a) > 1 else kw.get("values")
        elif fn_name.startswith("read_"):
            addr = a[0] if len(a) > 0 else kw.get("address")
            count = kw.get("count") or (a[1] if len(a) > 1 else None)
        ok = result is not None and not (hasattr(result, "isError") and result.isError())
        error = None if ok else explain_exception(result)
        resp = ""
        if ok and result:
            if hasattr(result, "registers") and result.registers: resp = " ".join(f"{r:04X}" for r in result.registers[:20])
            elif hasattr(result, "bits") and result.bits: resp = "".join("1" if b else "0" for b in result.bits[:16])
        rec = {"time": datetime.now(), "fc_num": fc_num, "fc_desc": fc_desc,
               "addr": addr, "count": count, "values": values, "ok": ok,
               "error": error, "ms": dt, "response": resp}
        self.inspector.record(**rec)
        try: self._pending_traffic.put_nowait(rec)
        except queue.Full: pass
        with self._stats_lock: self.stats["last_ms"] = dt
        return result

    def _drain_traffic(self):
        n = 0
        while n < 100:
            try: rec = self._pending_traffic.get_nowait()
            except queue.Empty: break
            if hasattr(self, "traffic_view"):
                try: self.traffic_view.add(rec)
                except: pass
            n += 1
        try: self.root.after(100, self._drain_traffic)
        except tk.TclError: pass

    def _read_entry_raw(self, entry):
        if not self.conn.connected: return None
        n = reg_count(entry.fmt)
        uid = entry.slave_id if entry.slave_id is not None else self._uid()
        try:
            if entry.fc == "Holding Registers":
                rr = self._call(self.conn.client.read_holding_registers, entry.addr, count=n, uid=uid); self._bump("reqs")
                if rr and not rr.isError(): return rr.registers
            elif entry.fc == "Input Registers":
                rr = self._call(self.conn.client.read_input_registers, entry.addr, count=n, uid=uid); self._bump("reqs")
                if rr and not rr.isError(): return rr.registers
            elif entry.fc == "Coils":
                rr = self._call(self.conn.client.read_coils, entry.addr, count=n, uid=uid); self._bump("reqs")
                if rr and not rr.isError(): return [1 if b else 0 for b in rr.bits[:n]]
            elif entry.fc == "Discrete Inputs":
                rr = self._call(self.conn.client.read_discrete_inputs, entry.addr, count=n, uid=uid); self._bump("reqs")
                if rr and not rr.isError(): return [1 if b else 0 for b in rr.bits[:n]]
            self._bump("errs")
        except: self._bump("errs")
        return None

    def _apply_read_result(self, e, raw):
        if e not in self.watch: return
        e.read_count += 1
        val = decode_value(raw, e.fmt, e.order)
        old_val = e.last_val
        if val is None and old_val is not None:
            e.health = "\u26a0 invalid value"; e.health_color = "#fc4"
            e.last_raw = raw; e.last_read_at = time.time()
            for iid, en in self.watch_items.items():
                if en is e:
                    self.watch_tv.item(iid, values=self._row_values(e), tags=("warning",))
                    break
            if hasattr(self, "details") and self.details.current is e:
                try: self.details.show(e)
                except: pass
            return
        health, trend, color = "\u2014", "\u2014", "#888"
        if e.fmt in ("ASCII","Hex","Binary"): health, color = "\u2139 info", "#8cf"
        elif e.fc in ("Coils","Discrete Inputs"):
            state = int(val) if isinstance(val, (int,float)) else 0
            health, color = ("\u2713 ON" if state else "\u25cb OFF"), ("#4c4" if state else "#888")
        elif isinstance(val, (int, float)):
            scaled = fmt_scale(val, e.scale) if e.scale != 1.0 else val
            if e.min_observed is None or scaled < e.min_observed: e.min_observed = scaled
            if e.max_observed is None or scaled > e.max_observed: e.max_observed = scaled
            health, color = "\u2713 normal", "#4c4"
            if e.warn_min is not None and scaled < e.warn_min: health, color = "\u26a0 low", "#fc4"
            elif e.warn_max is not None and scaled > e.warn_max: health, color = "\u26a0 high", "#fc4"
            if e.normal_min is not None and scaled < e.normal_min: health, color = "\U0001f6a8 CRITICAL LOW", "#f55"
            elif e.normal_max is not None and scaled > e.normal_max: health, color = "\U0001f6a8 CRITICAL HIGH", "#f55"
            if isinstance(old_val, (int, float)):
                old_scaled = fmt_scale(old_val, e.scale) if e.scale != 1.0 else old_val
                diff = scaled - old_scaled
                if abs(diff) < max(0.001, abs(scaled) * 0.001): trend = "\u2192 stable"
                elif diff > 0: trend = f"\u2191 +{diff:.3g}"
                else: trend = f"\u2193 {diff:.3g}"
        if old_val is not None and old_val != val: e.last_change_at = time.time()
        e.prev_val = old_val; e.last_val = val; e.last_raw = raw; e.last_read_at = time.time()
        e.health = health; e.trend = trend; e.health_color = color
        if isinstance(val, (int, float)):
            scaled = fmt_scale(val, e.scale) if e.scale != 1.0 else val
            e.history.append(float(scaled))
        tag = ""
        if health.startswith("\U0001f6a8"): tag = "critical"
        elif health.startswith("\u26a0"): tag = "warning"
        elif old_val is not None and old_val != val: tag = "changed"
        elif old_val is None: tag = "fresh"
        for iid, en in self.watch_items.items():
            if en is e:
                self.watch_tv.item(iid, values=self._row_values(e), tags=(tag,) if tag else ())
                break
        if hasattr(self, "details") and self.details.current is e:
            try: self.details.show(e)
            except: pass
        if self.logger and self.logger.enabled: self.logger.log_reading(e)
        if self.mqtt and self.mqtt.enabled: self.mqtt.publish_reading(e)

    def _do_write_and_show(self, e, new_str, on_done=None):
        if self.write_guard.is_locked():
            messagebox.showerror("E-STOP LOCK", "Emergency lock active.", parent=self.root); return
        if e.fc not in WRITABLE:
            messagebox.showerror("Read-only", f"{e.fc} does not support writes.", parent=self.root); return
        if not self.conn.connected:
            messagebox.showwarning("Disconnected", "Connect to the PLC before writing.", parent=self.root); return
        try:
            encoded = encode_value(new_str, e.fmt, e.order)
        except Exception as ex:
            messagebox.showerror("Encode error", str(ex), parent=self.root); return
        self.log(f"[->] Writing {e.name} @ {e.addr} = {new_str}")
        def worker():
            self.write_guard.check_rate()
            result = self._write_verify(e, new_str)
            try: self.root.after(0, lambda: self._after_write(e, result, on_done))
            except tk.TclError: pass
        threading.Thread(target=worker, daemon=True).start()

    def _after_write(self, e, result, on_done):
        try:
            if result.get("ok") and result.get("old_raw") is not None:
                self.write_guard.push_undo(e, result.get("old_raw"))
            self.show_write_result(e, result)
            self.add_history(e, result)
            if self.logger and self.logger.enabled: self.logger.log_write(e, result)
            if result.get("verified"): self.log(f"[OK] Verified: {e.name} = {result.get('new')}")
            elif result.get("ok"): self.log(f"[!] Mismatch: {e.name}")
            else: self.log(f"[X] Failed: {e.name} \u2014 {result.get('error')}")
            self._update_stats_light()
            if on_done: on_done(e, result)
        except tk.TclError: pass

    def _write_verify(self, e, new_str):
        if e.fc not in WRITABLE: return {"ok": False, "error": "Read-only function code"}
        if not isinstance(e.addr, int) or not 0 <= e.addr <= 65535: return {"ok": False, "error": "Invalid address"}
        old_raw = self._read_entry_raw(e)
        old_val = decode_value(old_raw, e.fmt, e.order) if old_raw else None
        old_disp = fmt_scale(old_val, e.scale)
        if e.fc == "Coils":
            try:
                coil_bool = bool(int(float(new_str)))
            except Exception:
                return {"ok": False, "error": f"Invalid coil value: {new_str}"}
            regs = [1 if coil_bool else 0]
        else:
            try: regs = encode_value(new_str, e.fmt, e.order)
            except Exception as ex: return {"ok": False, "error": f"Invalid value: {ex}"}
            coil_bool = None
        uid = e.slave_id if e.slave_id is not None else self._uid()
        try:
            if e.fc == "Holding Registers":
                if len(regs) == 1: rr = self._call(self.conn.client.write_register, e.addr, regs[0], uid=uid)
                else: rr = self._call(self.conn.client.write_registers, e.addr, regs, uid=uid)
            elif e.fc == "Coils":
                rr = self._call(self.conn.client.write_coil, e.addr, coil_bool, uid=uid)
            else: return {"ok": False, "error": "Read-only"}
            self._bump("writes")
            if not rr or rr.isError():
                return {"ok": False, "error": explain_exception(rr) or "Write failed",
                        "old": old_disp, "old_raw": old_val}
            new_raw = None; verified = False
            for attempt in range(3):
                time.sleep(0.15 * (attempt + 1))
                new_raw = self._read_entry_raw(e)
                if new_raw and new_raw[:len(regs)] == regs:
                    verified = True; break
            if new_raw is None:
                return {"ok": True, "verified": False, "old": old_disp, "old_raw": old_val, "new": None,
                        "error": "Write sent but read-back failed"}
            new_val = decode_value(new_raw, e.fmt, e.order)
            new_disp = fmt_scale(new_val, e.scale)
            if verified: self._bump("verified")
            else: self._bump("failed")
            if verified: rc, rt = "match", ""
            else:
                rc, rt = "mismatch", f"Sent {' '.join(f'{r:04X}' for r in regs)}, got {' '.join(f'{r:04X}' for r in new_raw)}"
            return {"ok": True, "verified": verified, "old": old_disp, "old_raw": old_val,
                    "new": new_disp, "raw": new_raw, "expected": regs, "reason_code": rc, "reason_text": rt}
        except Exception as ex:
            return {"ok": False, "error": str(ex), "old": old_disp, "old_raw": old_val}

    def _existing_names(self): return {e.name for e in self.watch}
    def add_watch(self):
        dlg = WatchDialog(self.root, existing_names=self._existing_names())
        if dlg.result:
            self.watch.append(dlg.result); self._render_watch_row(dlg.result)
            self._apply_filter()
    def edit_watch(self):
        sel = self.watch_tv.selection()
        if not sel: return
        e = self.watch_items.get(sel[0])
        if not e: return
        others = {x.name for x in self.watch if x is not e}
        dlg = WatchDialog(self.root, e, existing_names=others)
        if dlg.result:
            idx = self.watch.index(e); self.watch[idx] = dlg.result
            self.watch_items[sel[0]] = dlg.result
            self.watch_tv.item(sel[0], values=self._row_values(dlg.result))
            self._apply_filter()
            self._on_watch_select()
    def remove_watch(self):
        for item in list(self.watch_tv.selection()):
            e = self.watch_items.pop(item, None)
            if e is not None and e in self.watch: self.watch.remove(e)
            self.watch_tv.delete(item)
        self.details.show(None)
    def _render_watch_row(self, e):
        iid = self.watch_tv.insert("", tk.END, values=self._row_values(e))
        self.watch_items[iid] = e; return iid
    def _row_values(self, e):
        if e.last_val is None: val = scaled = "\u2014"
        else:
            val = str(e.last_val)
            if isinstance(e.last_val, (int, float)):
                scaled = f"{fmt_scale(e.last_val, e.scale):.3f}" if e.scale != 1.0 else str(e.last_val)
            else: scaled = str(e.last_val)
        age = fmt_uptime(time.time() - e.last_read_at) if e.last_read_at else "\u2014"
        slave_disp = e.slave_id if e.slave_id is not None else "\u2014"
        return (e.name, e.description or "\u2014", e.fc, e.addr, slave_disp, val, scaled, e.unit, e.health, e.trend, age)
    def _apply_filter(self):
        f = self.filter_var.get().lower().strip()
        for iid in self.watch_tv.get_children(): self.watch_tv.detach(iid)
        for e in self.watch:
            iid = next((i for i, en in self.watch_items.items() if en is e), None)
            if not iid: continue
            show = (not f or f in e.name.lower() or f in (e.description or "").lower()
                    or f in str(e.addr) or f in e.fc.lower())
            if show: self.watch_tv.reattach(iid, "", "end")
    def _on_watch_select(self, event=None):
        sel = self.watch_tv.selection()
        if sel: self.details.show(self.watch_items.get(sel[0]))
    def _watch_context_menu(self, event):
        iid = self.watch_tv.identify_row(event.y)
        if not iid: return
        self.watch_tv.selection_set(iid)
        e = self.watch_items.get(iid)
        if not e: return
        m = tk.Menu(self.root, tearoff=0)
        m.add_command(label="Write", command=self.write_watch_selected)
        m.add_command(label="Read Now", command=lambda: self.poller.read_once([e]))
        m.add_separator()
        for p in PRESETS: m.add_command(label=f"Preset {p}", command=lambda v=p: self._write_preset(e, v))
        m.add_separator()
        m.add_command(label="Edit Bits", command=self.edit_bits)
        m.add_command(label="Add to Graph", command=lambda: self._add_to_graph(e))
        m.add_command(label="Edit Register", command=self.edit_watch)
        m.add_command(label="Remove", command=self.remove_watch)
        m.tk_popup(event.x_root, event.y_root)
    def _add_to_graph(self, e):
        if not HAS_MPL:
            messagebox.showerror("matplotlib", "pip install matplotlib"); return
        w = GraphWindow(self.root, self); w.select_var.set(e.name); w._add()
    def _write_preset(self, e, value):
        if e.fc not in WRITABLE:
            messagebox.showinfo("Read-only", f"{e.fc} cannot be written."); return
        self._do_write_and_show(e, str(value))
    def read_watch_all(self):
        if not self.conn.connected:
            messagebox.showwarning("Disconnected", "Connect first."); return
        self.poller.read_once(list(self.watch))
    def write_watch_selected(self):
        sel = self.watch_tv.selection()
        if not sel: return
        e = self.watch_items.get(sel[0])
        if not e: return
        if e.fc not in WRITABLE:
            messagebox.showerror("Read-only", f"{e.fc} cannot be written."); return
        cur = e.last_val if e.last_val is not None else "\u2014"
        cur_disp = fmt_scale(cur, e.scale) if isinstance(cur, (int, float)) and e.scale != 1.0 else cur
        new = simpledialog.askstring("Write to PLC",
            f"Write to {e.name} @ {e.addr}\n"
            f"Function: {e.fc}    Format: {e.fmt}    Order: {e.order}\n"
            f"Current RAW: {cur} {e.unit}\n"
            f"Current SCALED: {cur_disp} {e.unit}\n\n"
            f"Enter RAW value:",
            initialvalue=str(cur) if cur != "\u2014" else "", parent=self.root)
        if not new: return
        self._do_write_and_show(e, new)

    def show_write_result(self, e, result):
        win = tk.Toplevel(self.root)
        win.title(f"Write Result - {e.name}")
        win.geometry("560x460"); win.transient(self.root)
        f = ttk.Frame(win, padding=15); f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text=e.name, font=("Segoe UI", 12, "bold")).pack(anchor="w")
        sub = f"{e.fc} @ {e.addr}  \u2022  {e.fmt}  \u2022  {e.order}"
        if e.description: sub += f"\n{e.description}"
        ttk.Label(f, text=sub, foreground="#888").pack(anchor="w", pady=(0,10))
        verified = result.get("verified")
        if not result.get("ok"):
            ttk.Label(f, text="WRITE FAILED", foreground="#f55", font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=5)
            ttk.Label(f, text=result.get("error", "Unknown"), wraplength=520).pack(anchor="w", padx=10)
            ttk.Button(f, text="Close", command=win.destroy).pack(pady=15); return
        if verified:
            ttk.Label(f, text="WRITE VERIFIED", foreground="#4c4", font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=5)
        else:
            ttk.Label(f, text="WRITE NOT VERIFIED", foreground="#fc4", font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=5)
            if result.get("reason_text"):
                ttk.Label(f, text=result["reason_text"], wraplength=520, foreground="#fc4").pack(anchor="w", padx=10)
        grid = ttk.Frame(f); grid.pack(fill=tk.X, pady=12)
        for i, (lbl, key, fg) in enumerate([("Old value:", "old", "#888"),
                ("New value:", "new", "#4c4" if verified else "#fc4"),
                ("Read-Back (hex):", "raw", None), ("Expected (hex):", "expected", None)]):
            val = result.get(key)
            if val is None: continue
            ttk.Label(grid, text=lbl).grid(row=i, column=0, sticky="w")
            if key in ("raw", "expected"):
                txt = " ".join(f"{r:04X}" for r in val)
                ttk.Label(grid, text=txt, font=("Consolas", 9)).grid(row=i, column=1, padx=10, sticky="w")
            else:
                ttk.Label(grid, text=f"{val} {e.unit}", font=("Consolas", 10, "bold"), foreground=fg).grid(row=i, column=1, padx=10, sticky="w")
        ttk.Button(f, text="Close", command=win.destroy).pack(pady=10)

    def add_history(self, e, result):
        ts = datetime.now().strftime("%H:%M:%S")
        status = "verified" if result.get("verified") else ("failed" if not result.get("ok") else "mismatch")
        tag = "ok" if result.get("verified") else ("fail" if not result.get("ok") else "warn")
        self.history_tv.insert("", 0, values=(ts, e.name, e.addr, e.fc,
            str(result.get("old", "\u2014")), str(result.get("new", "\u2014")), status), tags=(tag,))
    def _clear_history(self): self.history_tv.delete(*self.history_tv.get_children())
    def _export_history(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path: return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(["Time","Name","Address","Function","Old","New","Status"])
            for iid in self.history_tv.get_children(): w.writerow(self.history_tv.item(iid, "values"))

    def _make_quick_entry(self):
        try: addr = int(self.qw_addr.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid address"); return None
        try:
            return WatchEntry(addr, self.qw_fc.get(), self.qw_fmt.get(), self.qw_order.get(), f"Quick@{addr}")
        except ValueError as ex:
            messagebox.showerror("Invalid", str(ex)); return None
    def _quick_read(self):
        if not self.conn.connected:
            messagebox.showwarning("Disconnected", "Connect first."); return
        e = self._make_quick_entry()
        if not e: return
        def worker():
            raw = self._read_entry_raw(e)
            try: self.root.after(0, lambda: self._show_quick_read(raw, e))
            except tk.TclError: pass
        threading.Thread(target=worker, daemon=True).start()
    def _show_quick_read(self, raw, e):
        if raw is None: self.qw_current.set("Read failed"); return
        val = decode_value(raw, e.fmt, e.order)
        disp = f"{val:.6f}" if isinstance(val, float) else str(val)
        self.qw_current.set(f"{disp}\nRaw: {' '.join(f'{r:04X}' for r in raw)}")
    def _quick_write(self):
        if not self.conn.connected:
            messagebox.showwarning("Disconnected", "Connect first."); return
        e = self._make_quick_entry()
        if not e: return
        val = self.qw_val.get().strip()
        if not val:
            messagebox.showerror("Error", "Enter a value"); return
        def on_done(entry, result):
            if result.get("verified"): self.qw_result_label.config(text=f"Verified \u2014 new: {result.get('new')}", foreground="#4c4")
            elif result.get("ok"): self.qw_result_label.config(text=f"Mismatch", foreground="#fc4")
            else: self.qw_result_label.config(text=f"Failed: {result.get('error')}", foreground="#f55")
        self._do_write_and_show(e, val, on_done)
    def edit_bits(self):
        sel = self.watch_tv.selection()
        if not sel: return
        e = self.watch_items.get(sel[0])
        if not e or e.fc != "Holding Registers":
            messagebox.showinfo("Bits", "Bit editor works on Holding Registers only."); return
        BitEditorDialog(self.root, self, e)

    def do_raw_read(self, key):
        if not self.conn.connected: return
        tab = self.raw_tabs[key]
        try: start = int(tab["start"].get()); count = int(tab["count"].get())
        except ValueError: return
        fmt, order = tab["fmt"].get(), tab["order"].get()
        def worker():
            try:
                if key == "Holding Registers":
                    rr = self._call(self.conn.client.read_holding_registers, start, count=count)
                    regs = rr.registers if (rr and not rr.isError()) else None
                elif key == "Input Registers":
                    rr = self._call(self.conn.client.read_input_registers, start, count=count)
                    regs = rr.registers if (rr and not rr.isError()) else None
                elif key == "Coils":
                    rr = self._call(self.conn.client.read_coils, start, count=count)
                    regs = [1 if b else 0 for b in rr.bits[:count]] if (rr and not rr.isError()) else None
                else:
                    rr = self._call(self.conn.client.read_discrete_inputs, start, count=count)
                    regs = [1 if b else 0 for b in rr.bits[:count]] if (rr and not rr.isError()) else None
            except Exception as ex:
                self.root.after(0, lambda m=str(ex): self.log(f"[!] {m}")); return
            self.root.after(0, lambda: self._populate_raw(key, start, regs, fmt, order))
        threading.Thread(target=worker, daemon=True).start()
    def _populate_raw(self, key, start, regs, fmt, order):
        tv = self.raw_tabs[key]["tv"]
        for i in tv.get_children(): tv.delete(i)
        if regs is None: self.log(f"[!] read {key} failed"); return
        step = reg_count(fmt)
        for i in range(0, len(regs), step):
            chunk = regs[i:i+step]
            if len(chunk) < step: break
            val = decode_value(chunk, fmt, order)
            raw_str = " ".join(f"{r:04X}" for r in chunk)
            disp = f"{val:.6f}" if isinstance(val, float) else str(val)
            tv.insert("", tk.END, values=(start + i, raw_str, disp, self._guess_meaning(start + i, val)))
    def _guess_meaning(self, addr, val):
        for e in self.watch:
            if e.addr == addr: return f"{e.name} {e.unit}".strip()
        return ""
    def do_raw_write(self, key):
        if key not in WRITABLE: return
        tab = self.raw_tabs[key]
        sel = tab["tv"].selection()
        if not sel: return
        addr = int(tab["tv"].item(sel[0], "values")[0])
        fmt, order = tab["fmt"].get(), tab["order"].get()
        new = simpledialog.askstring("Write",
            f"Write to {key} @ {addr}\nFormat: {fmt}\n\nEnter new value:", parent=self.root)
        if not new: return
        try:
            e = WatchEntry(addr, key, fmt, order, f"Raw@{addr}")
        except ValueError as ex:
            messagebox.showerror("Invalid", str(ex)); return
        def on_done(entry, result):
            if result.get("ok"): self.do_raw_read(key)
        self._do_write_and_show(e, new, on_done)
    def toggle_polling(self, force_stop=False):
        if self.polling or force_stop:
            self.polling = False; self.poller.stop(); self.log("[-] Polling stopped"); return
        if not self.conn.connected:
            messagebox.showwarning("Disconnected", "Connect first."); return
        try: interval = max(200, int(self.scan_var.get()))
        except: interval = 1000
        self.polling = True; self.poller.start(interval); self.log(f"[+] Polling started ({interval} ms)")
    def _start_health_monitor(self):
        def _check():
            if (self._was_connected and self.auto_reconnect and not self.conn.connected
                    and not self.write_guard.is_locked() and self.mode_var.get() == "TCP"):
                try:
                    if self.conn.connect(self.mode_var.get(), host=self.host_var.get().strip(),
                            port=int(self.port_var.get()), com=self.com_var.get().strip(),
                            baud=int(self.baud_var.get())):
                        self.status_var.set(f"Reconnected ({self.mode_var.get()})")
                        self.status_lbl_widget.configure(foreground="#4c4")
                        self.log("[+] Auto-reconnected")
                except: pass
            try: self.health_monitor_id = self.root.after(5000, _check)
            except: pass
        self.health_monitor_id = self.root.after(5000, _check)
    def auto_detect(self):
        if not self.conn.connected:
            messagebox.showwarning("Disconnected", "Connect first."); return
        def worker():
            lines = ["=== Probing slave IDs ==="]
            for sid in [self._uid(), 1, 2, 3, 0, 255]:
                try:
                    rr = self.conn.call(self.conn.client.read_holding_registers, 0, count=2, uid=sid)
                    if rr and not rr.isError(): lines.append(f"  OK Slave {sid}: Holding[0..1] = {rr.registers}")
                except: pass
            lines.append("=== Probing registers ===")
            for addr in (0, 1, 100, 1000):
                for fc, name in [("read_holding_registers","Holding"),("read_input_registers","Input")]:
                    try:
                        rr = self._call(getattr(self.conn.client, fc), addr, count=1)
                        if rr and not rr.isError(): lines.append(f"  OK {name}@{addr} = {rr.registers[0]}")
                    except: pass
            if len(lines) <= 2: lines.append("  No device responded.")
            self.root.after(0, lambda: messagebox.showinfo("Auto-Detect", "\n".join(lines)))
        threading.Thread(target=worker, daemon=True).start()
    def open_scanner(self): ScannerDialog(self.root, self)
    def open_manual_control(self): ManualControlWindow(self.root, self)
    def open_macro_editor(self): MacroEditorWindow(self.root, self)
    def open_ramp_window(self): RampWindow(self.root, self)
    def open_discovery(self): DiscoveryWizard(self.root, self)

    def import_file(self):
        path = filedialog.askopenfilename(title="Import Register Map",
            filetypes=[("Excel/CSV","*.xlsx *.xlsm *.csv"), ("All","*.*")])
        if not path: return
        count = 0; skipped = 0
        try:
            rows = []
            if path.lower().endswith(".csv"):
                with open(path, encoding="utf-8-sig") as fh:
                    for r in csv.DictReader(fh): rows.append({(k or "").lower().strip(): v for k, v in r.items()})
            else:
                if not HAS_XL: messagebox.showerror("Missing", "pip install openpyxl"); return
                wb = openpyxl.load_workbook(path, data_only=True); ws = wb.active
                headers = [str(c.value or "").strip().lower() for c in ws[1]]
                for r in ws.iter_rows(min_row=2, values_only=True):
                    rows.append({headers[i]: r[i] for i in range(len(headers))})
            seen = {e.name for e in self.watch}
            for row in rows:
                name = str(row.get("name") or row.get("tag") or "").strip()
                try: addr = int(str(row.get("address") or row.get("addr") or 0).strip(), 0)
                except: continue
                if not 0 <= addr <= 65535: continue
                fc_raw = str(row.get("function") or "holding").strip().lower()
                if "input" in fc_raw and "discrete" not in fc_raw: fc = "Input Registers"
                elif "coil" in fc_raw: fc = "Coils"
                elif "disc" in fc_raw: fc = "Discrete Inputs"
                else: fc = "Holding Registers"
                fmt_raw = str(row.get("format") or "UInt16").strip()
                fmt = fmt_raw if fmt_raw in FORMATS else "UInt16"
                try: scale = float(row.get("scale") or 1.0)
                except: scale = 1.0
                unit = str(row.get("unit") or "").strip()
                order = str(row.get("order") or "ABCD").strip()
                if order not in BYTE_ORDERS: order = "ABCD"
                desc = str(row.get("description") or row.get("desc") or "").strip()
                def _pf(v):
                    try: return float(v) if v not in (None, "") else None
                    except: return None
                slave_raw = row.get("slave") if row.get("slave") not in (None, "") else row.get("slave_id")
                try: slave = int(slave_raw) if slave_raw not in (None, "") else None
                except: slave = None
                fname = name or f"R{addr}"
                if fname in seen: skipped += 1; continue
                try:
                    entry = WatchEntry(addr, fc, fmt, order, fname, scale, unit, slave_id=slave,
                                        description=desc, normal_min=_pf(row.get("normal_min")),
                                        normal_max=_pf(row.get("normal_max")), warn_min=_pf(row.get("warn_min")),
                                        warn_max=_pf(row.get("warn_max")))
                except ValueError: skipped += 1; continue
                seen.add(fname)
                self.watch.append(entry); self._render_watch_row(entry); count += 1
            self._apply_filter()
            messagebox.showinfo("Import", f"Imported {count} registers. Skipped {skipped}.")
        except Exception as e: messagebox.showerror("Import failed", str(e))
    def save_project(self):
        path = filedialog.asksaveasfilename(defaultextension=".mbproj",
            filetypes=[("Modbus Project","*.mbproj"), ("JSON","*.json")])
        if not path: return
        data = {"version": 9.4,
                "connection": {"mode": self.mode_var.get(), "host": self.host_var.get(),
                               "port": self.port_var.get(), "com": self.com_var.get(),
                               "baud": self.baud_var.get(), "unit": self.unit_var.get(),
                               "scan": self.scan_var.get()},
                "watch": [w.to_dict() for w in self.watch]}
        with open(path, "w", encoding="utf-8") as f: json.dump(data, f, indent=2, ensure_ascii=False)
        self.log(f"[+] Project saved: {path}")
    def load_project(self):
        path = filedialog.askopenfilename(filetypes=[("Modbus Project","*.mbproj"), ("JSON","*.json")])
        if not path: return
        with open(path, encoding="utf-8") as f: data = json.load(f)
        c = data.get("connection", {})
        self.mode_var.set(c.get("mode","TCP")); self.host_var.set(c.get("host","127.0.0.1"))
        self.port_var.set(c.get("port","502")); self.com_var.set(c.get("com","COM1"))
        self.baud_var.set(c.get("baud","9600")); self.unit_var.set(c.get("unit","1"))
        self.scan_var.set(c.get("scan","1000")); self._on_mode()
        self.watch.clear(); self.watch_items.clear()
        for i in self.watch_tv.get_children(): self.watch_tv.delete(i)
        for wd in data.get("watch", []):
            try: e = WatchEntry.from_dict(wd)
            except: continue
            self.watch.append(e); self._render_watch_row(e)
        self._apply_filter()
        self.log(f"[+] Project loaded: {path}")
    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path: return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Name","Description","Function","Address","Slave","Value","Scaled","Unit","Health","Trend","Normal Min","Normal Max","Observed Min","Observed Max"])
            for e in self.watch:
                val = e.last_val
                scaled = fmt_scale(val, e.scale) if isinstance(val, (int, float)) else val
                slave_disp = e.slave_id if e.slave_id is not None else ""
                w.writerow([e.name, e.description, e.fc, e.addr, slave_disp, val, scaled, e.unit,
                            e.health, e.trend, e.normal_min, e.normal_max, e.min_observed, e.max_observed])
        self.log(f"[+] CSV exported: {path}")
    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        line = f"[{ts}] {msg}\n"
        self._log_lines.append(line)
        if hasattr(self, "log_text"):
            try: self.log_text.insert(tk.END, line); self.log_text.see(tk.END)
            except: pass
        if self.logger and self.logger.enabled:
            try: self.logger.log_event("info", "app", msg)
            except: pass
    def _update_stats_light(self):
        try:
            if hasattr(self, "stat_lbl"):
                with self._stats_lock:
                    parts = [f"Writes {self.stats['writes']}  OK {self.stats['verified']}  X {self.stats['failed']}"]
                self.stat_lbl.config(text="  |  ".join(parts))
        except: pass
    def _update_stats(self):
        try:
            uptime = int(time.time() - self.stats["since"])
            with self._stats_lock: s = dict(self.stats)
            parts = [f"Up {fmt_uptime(uptime)}", f"Reqs {s['reqs']}  Err {s['errs']}",
                     f"Writes {s['writes']}  OK {s['verified']}  X {s['failed']}",
                     f"{s['last_ms']}ms", "Polling" if self.polling else "Idle",
                     f"Traffic {len(self.inspector.get_all())}"]
            self.stat_lbl.config(text="  |  ".join(parts))
            self._stats_id = self.root.after(1000, self._update_stats)
        except: pass
    def on_close(self):
        self.toggle_polling(force_stop=True); self.stop_scan()
        self.macro_runner.stop(); self.ramp_runner.stop()
        if self.health_monitor_id:
            try: self.root.after_cancel(self.health_monitor_id)
            except: pass
        if self._stats_id:
            try: self.root.after_cancel(self._stats_id)
            except: pass
        try: self.mqtt.disconnect()
        except: pass
        try: self.logger.stop()
        except: pass
        self.conn.disconnect(); self.root.destroy()


if __name__ == "__main__":
    if not HAS_PYM: print("pymodbus not installed \u2014 pip install 'pymodbus>=3.0'")
    root = tk.Tk(); root.withdraw()
    dlg = StartupDialog(root)
    if dlg.result is None:
        root.destroy(); raise SystemExit(0)
    app = ModbusProApp(root, startup=dlg.result)
    root.deiconify()
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()