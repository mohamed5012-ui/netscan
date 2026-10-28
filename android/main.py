# -*- coding: utf-8 -*-
"""
ماسح أجهزة الشبكة — تطبيق أندرويد (Kivy) → netscan.apk
واجهة عربية: مسح الشبكة، عمود ملاحظات (IP متكرر/MAC مكرر/متشابه/عشوائي)،
وزرار تصدير CSV لمجلد التنزيلات.

ملاحظة أندرويد: من أندرويد 10 فما فوق، التطبيقات العادية (بدون روت) ممنوعة
من قراءة جدول ARP — ده قيد من جوجل على كل التطبيقات. فالتطبيق بيكتشف
الأجهزة الحيّة وعناوين الـ IP عن طريق فحص TCP (شغّال من غير روت)،
وعنوان الـ MAC بيظهر على حسب ما النظام يسمح.
"""

import os
import sys
import socket
import ipaddress
import threading
import errno
import time
import gzip
import traceback


# ---- مصيدة الأخطاء: تكتب أي كراش في ملف يسهل الوصول له ----
def _dump_error(text):
    for p in ("/sdcard/Download/netscan_error.txt",
              "/storage/emulated/0/Download/netscan_error.txt",
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "netscan_error.txt")):
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
        except Exception:
            continue


def _excepthook(etype, value, tb):
    try:
        _dump_error("".join(traceback.format_exception(etype, value, tb)))
    except Exception:
        pass
    sys.__excepthook__(etype, value, tb)


sys.excepthook = _excepthook

from kivy.app import App
from kivy.clock import Clock
from kivy.core.text import LabelBase
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.uix.progressbar import ProgressBar
from kivy.graphics import Color, Rectangle

# ---- دعم العربية ----
try:
    import arabic_reshaper
    from bidi.algorithm import get_display

    def ar(t):
        try:
            return get_display(arabic_reshaper.reshape(str(t)))
        except Exception:
            return str(t)
except Exception:
    def ar(t):
        return str(t)

FONT = "Roboto"
try:
    _dir = os.path.dirname(os.path.abspath(__file__))
    _reg = os.path.join(_dir, "Cairo.ttf")
    _bold = os.path.join(_dir, "Cairo-Bold.ttf")
    if os.path.exists(_reg):
        LabelBase.register(
            name="Cairo",
            fn_regular=_reg,
            fn_bold=_bold if os.path.exists(_bold) else _reg,
        )
        FONT = "Cairo"
except Exception:
    FONT = "Roboto"

BG = (0.059, 0.090, 0.165, 1)
PANEL = (0.118, 0.161, 0.231, 1)
BLUE = (0.145, 0.388, 0.922, 1)
RED = (0.863, 0.149, 0.149, 1)
TXT = (0.886, 0.910, 0.941, 1)
MUT = (0.580, 0.639, 0.722, 1)
ME = (0.118, 0.227, 0.372, 1)
WARN = (0.247, 0.114, 0.114, 1)

PROBE_PORTS = [80, 443, 445, 8080, 22, 53, 139, 23, 7547, 8081, 554]


# ---------------------------------------------------------------------------
#  محرّك المسح
# ---------------------------------------------------------------------------

_OUI = None


def load_oui():
    global _OUI
    if _OUI is not None:
        return _OUI
    oui = {}
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendors.gz")
        with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "\t" in line:
                    k, v = line.rstrip("\n").split("\t", 1)
                    oui[k.strip().upper()] = v.strip()
    except Exception:
        pass
    _OUI = oui
    return oui


def vendor_of(mac):
    if not mac or mac == "—" or len(mac) < 8:
        return ""
    oui = load_oui()
    hexs = mac.upper().replace(":", "")
    for n in (9, 7, 6):
        if len(hexs) >= n and hexs[:n] in oui:
            return oui[hexs[:n]]
    return ""


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def normalize_mac(mac):
    mac = mac.lower().replace("-", ":").strip()
    p = mac.split(":")
    return ":".join(x.zfill(2) for x in p) if len(p) == 6 else mac


def read_arp():
    pairs = []
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.read().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] not in ("00:00:00:00:00:00",):
                    pairs.append((parts[0], normalize_mac(parts[3])))
    except Exception:
        pass
    return pairs


def is_random_mac(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def probe_host(ip):
    ip = str(ip)
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(0.1)
        u.sendto(b"\x00", (ip, 40000))
        u.close()
    except Exception:
        pass
    for port in PROBE_PORTS:
        try:
            t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            t.settimeout(0.22)
            rc = t.connect_ex((ip, port))
            t.close()
            if rc == 0 or rc == errno.ECONNREFUSED:
                return True
        except Exception:
            continue
    return False


def resolve_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def analyze_flags(devices):
    from collections import defaultdict
    by_mac = defaultdict(list)
    by_ip = defaultdict(list)
    prefix5 = defaultdict(set)
    for d in devices:
        if d["mac"] and d["mac"] != "—":
            by_mac[d["mac"]].append(d["ip"])
            if len(d["mac"]) == 17:
                prefix5[d["mac"][:14]].add(d["mac"])
        by_ip[d["ip"]].append(d["mac"])
    for d in devices:
        f = []
        mac, ip = d["mac"], d["ip"]
        if len(set(m for m in by_ip[ip] if m and m != "—")) > 1:
            f.append("IP متكرر")
        if mac and mac != "—":
            if len(set(by_mac[mac])) > 1:
                f.append("MAC مكرر")
            if len(prefix5.get(mac[:14], set())) > 1:
                f.append("MAC متشابه")
            if is_random_mac(mac):
                f.append("MAC عشوائي")
        d["flags"] = f
    return devices


def scan(network, progress_cb, done_cb, stop_flag):
    hosts = list(network.hosts())
    total = len(hosts)
    done = [0]
    alive = []
    lock = threading.Lock()
    idx = [0]

    def worker():
        while not stop_flag.is_set():
            with lock:
                if idx[0] >= total:
                    return
                ip = hosts[idx[0]]
                idx[0] += 1
            up = probe_host(ip)
            with lock:
                done[0] += 1
                progress_cb(done[0], total)
                if up:
                    alive.append(str(ip))

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(80)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if stop_flag.is_set():
        done_cb([])
        return

    arp = dict(read_arp())
    local_ip = get_local_ip()
    ips = set(alive) | {ip for ip, _ in read_arp() if _in(ip, network)}
    ips = sorted(ips, key=lambda x: int(ipaddress.ip_address(x)))

    devices = []
    for ip in ips:
        mac = arp.get(ip, "")
        devices.append({
            "ip": ip, "mac": mac or "—",
            "vendor": vendor_of(mac) or "—",
            "name": resolve_name(ip), "is_me": ip == local_ip, "flags": [],
        })
    analyze_flags(devices)
    done_cb(devices)


def _in(ip, net):
    try:
        return ipaddress.ip_address(ip) in net
    except Exception:
        return False


def export_csv(devices):
    """يحفظ CSV في مجلد التنزيلات (أندرويد) أو المجلد الحالي."""
    name = "netscan_devices.csv"
    paths = ["/sdcard/Download", "/storage/emulated/0/Download", "."]
    for base in paths:
        try:
            if os.path.isdir(base) or base == ".":
                p = os.path.join(base, name)
                with open(p, "w", encoding="utf-8-sig") as f:
                    f.write("IP,MAC,الشركة,اسم الجهاز,ملاحظات\n")
                    for d in devices:
                        f.write(f'{d["ip"]},{d["mac"]},{d.get("vendor","")},'
                                f'{d.get("name","")},{" / ".join(d.get("flags",[]))}\n')
                return p
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
#  الواجهة
# ---------------------------------------------------------------------------

def bg(w, color):
    with w.canvas.before:
        Color(*color)
        w._rect = Rectangle(pos=w.pos, size=w.size)
    w.bind(pos=lambda *a: setattr(w._rect, "pos", w.pos),
           size=lambda *a: setattr(w._rect, "size", w.size))


class Row(BoxLayout):
    def __init__(self, dev, **kw):
        super().__init__(orientation="horizontal", size_hint_y=None,
                         height=dp(58), padding=dp(6), **kw)
        if dev.get("is_me"):
            bg(self, ME)
        elif dev.get("flags"):
            bg(self, WARN)

        left = BoxLayout(orientation="vertical")
        title = dev["ip"] + ("  ← جهازك" if dev.get("is_me") else "")
        left.add_widget(Label(text=ar(title) if dev.get("is_me") else title,
                              font_name=FONT, color=TXT, font_size=dp(15), bold=True,
                              halign="left", valign="middle", text_size=(dp(165), None)))
        left.add_widget(Label(text=dev["mac"], font_name=FONT, color=MUT,
                              font_size=dp(11), halign="left", valign="middle",
                              text_size=(dp(165), None)))
        right = BoxLayout(orientation="vertical")
        right.add_widget(Label(text=ar(dev["vendor"]), font_name=FONT, color=TXT,
                               font_size=dp(13), halign="right", valign="middle",
                               text_size=(dp(150), None)))
        sub = dev.get("name") or ""
        if dev.get("flags"):
            sub = "⚠ " + " / ".join(dev["flags"])
        right.add_widget(Label(text=ar(sub) if dev.get("flags") else sub,
                               font_name=FONT,
                               color=(0.98, 0.7, 0.7, 1) if dev.get("flags") else MUT,
                               font_size=dp(11), halign="right", valign="middle",
                               text_size=(dp(150), None)))
        self.add_widget(left)
        self.add_widget(right)


class Root(BoxLayout):
    def __init__(self, **kw):
        super().__init__(orientation="vertical", **kw)
        bg(self, BG)
        self.stop_flag = threading.Event()
        self.scanning = False
        self.devices = []
        self._build()

    def _build(self):
        header = BoxLayout(size_hint_y=None, height=dp(52), padding=dp(10))
        header.add_widget(Label(text=ar("🔍  ماسح أجهزة الشبكة"), font_name=FONT,
                               color=TXT, font_size=dp(19), bold=True,
                               halign="right", valign="middle"))
        self.add_widget(header)

        ctrl = BoxLayout(size_hint_y=None, height=dp(52), padding=dp(8), spacing=dp(6))
        self.net = TextInput(text=str(self._guess()), multiline=False, font_name=FONT,
                             font_size=dp(14), halign="center", size_hint_x=0.4,
                             background_color=PANEL, foreground_color=TXT)
        self.btn = Button(text=ar("▶ مسح"), font_name=FONT, font_size=dp(14), bold=True,
                          size_hint_x=0.3, background_normal="", background_color=BLUE,
                          color=(1, 1, 1, 1))
        self.btn.bind(on_release=self.toggle)
        self.exp = Button(text=ar("💾 تصدير"), font_name=FONT, font_size=dp(13),
                          size_hint_x=0.3, background_normal="",
                          background_color=(0.2, 0.25, 0.33, 1), color=(1, 1, 1, 1),
                          disabled=True)
        self.exp.bind(on_release=self.export)
        ctrl.add_widget(self.btn)
        ctrl.add_widget(self.exp)
        ctrl.add_widget(self.net)
        self.add_widget(ctrl)

        self.pbar = ProgressBar(max=254, value=0, size_hint_y=None, height=dp(8))
        self.add_widget(self.pbar)
        self.status = Label(text=ar("جاهز"), font_name=FONT, color=MUT,
                            font_size=dp(12), size_hint_y=None, height=dp(24),
                            halign="right", valign="middle")
        self.add_widget(self.status)

        self.scroll = ScrollView()
        self.list = GridLayout(cols=1, spacing=dp(2), size_hint_y=None, padding=dp(4))
        self.list.bind(minimum_height=self.list.setter("height"))
        self.scroll.add_widget(self.list)
        self.add_widget(self.scroll)

    def _guess(self):
        ip = get_local_ip()
        if ip == "127.0.0.1":
            return "192.168.1.0/24"
        try:
            return ipaddress.ip_network(f"{ip}/24", strict=False)
        except Exception:
            return "192.168.1.0/24"

    def set_status(self, t):
        self.status.text = ar(t)

    def toggle(self, *a):
        if self.scanning:
            self.stop_flag.set()
            self.scanning = False
            self.btn.text = ar("▶ مسح")
            self.btn.background_color = BLUE
            self.set_status("جاري الإيقاف…")
            return
        self.start()

    def start(self):
        try:
            net = ipaddress.ip_network(self.net.text.strip(), strict=False)
        except Exception:
            self.set_status("نطاق غير صحيح — مثال: 192.168.1.0/24")
            return
        if net.num_addresses > 4096:
            self.set_status("الشبكة كبيرة — استخدم /24")
            return
        self.list.clear_widgets()
        self.devices = []
        self.stop_flag.clear()
        self.scanning = True
        self.btn.text = ar("■ إيقاف")
        self.btn.background_color = RED
        self.exp.disabled = True
        self.pbar.max = max(1, net.num_addresses - 2)
        self.pbar.value = 0
        self.set_status("جاري المسح…")
        threading.Thread(target=self._run, args=(net,), daemon=True).start()

    def _run(self, net):
        def pcb(d, t):
            Clock.schedule_once(lambda dt: self._prog(d, t), 0)

        def dcb(devs):
            Clock.schedule_once(lambda dt: self._done(devs), 0)

        scan(net, pcb, dcb, self.stop_flag)

    def _prog(self, d, t):
        self.pbar.value = d
        self.set_status(f"جاري المسح…  {d}/{t}")

    def _done(self, devs):
        self.scanning = False
        self.btn.text = ar("▶ مسح")
        self.btn.background_color = BLUE
        self.devices = devs
        for d in devs:
            self.list.add_widget(Row(d))
        if devs:
            self.exp.disabled = False
        issues = sum(1 for d in devs if d["flags"])
        if self.stop_flag.is_set():
            self.set_status(f"تم الإيقاف — {len(devs)} جهاز")
        else:
            self.pbar.value = self.pbar.max
            msg = f"تم ✓   عدد الأجهزة: {len(devs)}"
            if issues:
                msg += f"   |   ⚠ {issues} ملاحظات"
            self.set_status(msg)

    def export(self, *a):
        if not self.devices:
            return
        p = export_csv(self.devices)
        if p:
            self.set_status(f"💾 تم الحفظ: {p}")
        else:
            self.set_status("⚠ فشل التصدير — تأكد من صلاحية التخزين")


class NetScanApp(App):
    def build(self):
        self.title = "netscan"
        try:
            return Root()
        except Exception:
            # بدل ما التطبيق يقفل، نعرض الخطأ على الشاشة ونكتبه في ملف
            tb = traceback.format_exc()
            _dump_error(tb)
            from kivy.uix.scrollview import ScrollView as _SV
            from kivy.uix.label import Label as _L
            sv = _SV()
            lbl = _L(text="خطأ عند بدء التشغيل:\n\n" + tb,
                     halign="left", valign="top", font_size=dp(12),
                     color=(1, 0.8, 0.8, 1), size_hint_y=None, padding=(dp(10), dp(10)))
            lbl.bind(texture_size=lambda *a: setattr(lbl, "height", lbl.texture_size[1] + dp(20)),
                     width=lambda *a: setattr(lbl, "text_size", (lbl.width - dp(20), None)))
            sv.add_widget(lbl)
            return sv


def main():
    try:
        NetScanApp().run()
    except Exception:
        _dump_error(traceback.format_exc())
        raise


if __name__ == "__main__":
    main()
