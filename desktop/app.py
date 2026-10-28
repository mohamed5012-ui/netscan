#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماسح أجهزة الشبكة — واجهة سطح المكتب (تصميم مودرن) → netscan.exe
شكل "مركز مراقبة الشبكة": كروت للأجهزة، شارات ملوّنة للتنبيهات، لون تركوازي مميز.
المحرّك في core/scanner.py.
"""

import os
import sys
import ipaddress
import threading

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    from core import scanner
except Exception:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from core import scanner
    except Exception:
        import scanner  # type: ignore


# ================================  الألوان  ================================
BG       = "#0a0e14"   # خلفية عميقة
SURFACE  = "#121a24"   # كرت
SURFACE2 = "#0f1620"   # كرت بديل (تخطيط مخطّط)
LINE     = "#1e2a38"
TEAL     = "#2dd4bf"   # اللون المميز
TEALDK   = "#15b8a6"
SKY      = "#38bdf8"   # جهازك
RED      = "#f87171"
AMBER    = "#fbbf24"
TXT      = "#e8eef2"
MUT      = "#7d8b99"
FAINT    = "#4b5a68"

# شارات التنبيهات: (خلفية، نص)
CHIP = {
    "IP متكرر":   ("#7f1d1d", "#fecaca"),
    "MAC مكرر":   ("#7c2d12", "#fed7aa"),
    "MAC متشابه": ("#713f12", "#fde68a"),
    "MAC عشوائي": ("#334155", "#cbd5e1"),
}

MONO = "Consolas"
UI = "Segoe UI"


class ScrollList(tk.Frame):
    """قائمة قابلة للتمرير تحتوي كروت الأجهزة."""
    def __init__(self, master, **kw):
        super().__init__(master, bg=BG, **kw)
        self.canvas = tk.Canvas(self, bg=BG, highlightthickness=0, bd=0)
        self.sb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=BG)
        self.inner.bind("<Configure>",
                        lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.win, width=e.width))
        self.canvas.configure(yscrollcommand=self.sb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.sb.pack(side="right", fill="y")
        # عجلة الماوس
        self.canvas.bind_all("<MouseWheel>", self._wheel)
        self.canvas.bind_all("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind_all("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))

    def _wheel(self, e):
        self.canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

    def clear(self):
        for w in self.inner.winfo_children():
            w.destroy()


class NetScanApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("netscan — ماسح أجهزة الشبكة")
        self.geometry("960x620")
        self.minsize(820, 520)
        self.configure(bg=BG)

        self.stop_flag = threading.Event()
        self.scanning = False
        self.devices = []

        self._build()
        self._autodetect()

    # ---------------------------------------------------------------- واجهة
    def _build(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TScrollbar", background=LINE, troughcolor=BG,
                        bordercolor=BG, arrowcolor=MUT, relief="flat")
        style.configure("Teal.Horizontal.TProgressbar", troughcolor=SURFACE2,
                        background=TEAL, bordercolor=SURFACE2, thickness=6)

        # ===== الهيدر =====
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=22, pady=(18, 0))

        mark = tk.Canvas(header, width=34, height=34, bg=BG, highlightthickness=0)
        mark.pack(side="right", padx=(10, 0))
        # علامة "رادار" بسيطة
        mark.create_oval(4, 4, 30, 30, outline=TEAL, width=2)
        mark.create_oval(11, 11, 23, 23, outline=TEALDK, width=2)
        mark.create_oval(15, 15, 19, 19, fill=TEAL, outline="")
        mark.create_line(17, 17, 29, 7, fill=TEAL, width=2)

        titlebox = tk.Frame(header, bg=BG)
        titlebox.pack(side="right")
        tk.Label(titlebox, text="ماسح أجهزة الشبكة", bg=BG, fg=TXT,
                 font=(UI, 18, "bold")).pack(anchor="e")
        tk.Label(titlebox, text="NETSCAN  ·  مراقبة الأجهزة المتصلة", bg=BG, fg=TEAL,
                 font=(UI, 9)).pack(anchor="e")

        # خط تحت الهيدر
        tk.Frame(self, bg=LINE, height=1).pack(fill="x", padx=22, pady=(14, 0))

        # ===== صف التحكم =====
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=22, pady=14)

        tk.Label(bar, text="النطاق", bg=BG, fg=MUT, font=(UI, 9)).pack(side="right", padx=(10, 6))
        self.net_var = tk.StringVar()
        ent = tk.Frame(bar, bg=SURFACE, highlightbackground=LINE, highlightthickness=1)
        ent.pack(side="right")
        self.net_entry = tk.Entry(ent, textvariable=self.net_var, width=20, justify="center",
                                  font=(MONO, 11), bg=SURFACE, fg=TEAL, relief="flat",
                                  insertbackground=TEAL, disabledbackground=SURFACE)
        self.net_entry.pack(padx=10, ipady=6)

        self.scan_btn = tk.Button(bar, text="▶  ابدأ المسح", command=self.toggle,
                                  bg=TEAL, fg="#04131a", relief="flat",
                                  font=(UI, 11, "bold"), padx=20, pady=7, bd=0,
                                  activebackground=TEALDK, activeforeground="#04131a",
                                  cursor="hand2")
        self.scan_btn.pack(side="left")

        self.export_btn = tk.Button(bar, text="⤓  تصدير", command=self.export,
                                    bg=SURFACE, fg=MUT, relief="flat",
                                    font=(UI, 10), padx=14, pady=7, bd=0,
                                    activebackground=LINE, activeforeground=TXT,
                                    cursor="hand2", state="disabled",
                                    highlightbackground=LINE, highlightthickness=1)
        self.export_btn.pack(side="left", padx=8)

        self.issues_var = tk.BooleanVar(value=False)
        self.issues_cb = tk.Checkbutton(
            bar, text="التنبيهات فقط", variable=self.issues_var, command=self._render,
            bg=BG, fg=MUT, selectcolor=SURFACE, activebackground=BG,
            activeforeground=TXT, font=(UI, 9), bd=0, highlightthickness=0)
        self.issues_cb.pack(side="left", padx=6)

        # ===== شريط إحصاء =====
        self.stats = tk.Frame(self, bg=BG)
        self.stats.pack(fill="x", padx=22, pady=(0, 8))
        self.stat_total = self._pill(self.stats, "0", "جهاز", TEAL)
        self.stat_issue = self._pill(self.stats, "0", "تنبيه", AMBER)

        # ===== القائمة =====
        self.list = ScrollList(self)
        self.list.pack(fill="both", expand=True, padx=16, pady=(0, 6))

        # ===== الحالة =====
        foot = tk.Frame(self, bg=BG)
        foot.pack(fill="x", padx=22, pady=(0, 14))
        self.progress = ttk.Progressbar(foot, style="Teal.Horizontal.TProgressbar",
                                        mode="determinate")
        self.progress.pack(fill="x", pady=(0, 7))
        self.status = tk.Label(foot, text="جاهز", bg=BG, fg=MUT, font=(UI, 9), anchor="e")
        self.status.pack(fill="x")

    def _pill(self, parent, num, label, color):
        box = tk.Frame(parent, bg=SURFACE, highlightbackground=LINE, highlightthickness=1)
        box.pack(side="right", padx=(8, 0))
        n = tk.Label(box, text=num, bg=SURFACE, fg=color, font=(UI, 12, "bold"))
        n.pack(side="left", padx=(12, 4), pady=4)
        tk.Label(box, text=label, bg=SURFACE, fg=MUT, font=(UI, 9)).pack(side="left", padx=(0, 12))
        return n

    # ------------------------------------------------------------ منطق
    def _autodetect(self):
        local_ip, net = scanner.detect_network()
        if not net:
            self.net_var.set("192.168.1.0/24")
            self._set("مش لاقي شبكة — اتأكد إنك متصل")
        else:
            self.net_var.set(str(net))
            self._set(f"جهازك {local_ip}   ·   الشبكة {net}")

    def _set(self, t):
        self.status.config(text=t)

    def toggle(self):
        if self.scanning:
            self.stop_flag.set()
            self.scan_btn.config(text="▶  ابدأ المسح", bg=TEAL)
            self._set("جاري الإيقاف…")
            self.scanning = False
            return
        self.start()

    def start(self):
        try:
            network = ipaddress.ip_network(self.net_var.get().strip(), strict=False)
        except Exception:
            messagebox.showerror("خطأ", "نطاق الشبكة غير صحيح.\nمثال: 192.168.1.0/24")
            return
        if network.num_addresses > scanner.MAX_ADDRESSES:
            messagebox.showwarning("تنبيه", "الشبكة كبيرة جدًا.\nاستخدم نطاق أصغر.")
            return

        self.list.clear()
        self.devices = []
        self.stop_flag.clear()
        self.scanning = True
        self.scan_btn.config(text="■  إيقاف", bg=RED, activebackground="#dc2626")
        self.export_btn.config(state="disabled", fg=MUT)
        self.progress.config(value=0, maximum=max(1, network.num_addresses - 2))
        self._set("جاري المسح…")
        threading.Thread(target=self._run, args=(network,), daemon=True).start()

    def _run(self, network):
        def pcb(done, total):
            self.after(0, lambda: self._prog(done, total))
        try:
            self.devices = scanner.scan_network(
                network, progress_cb=pcb, stop_flag=self.stop_flag, do_names=True)
        finally:
            self.after(0, self._done)

    def _prog(self, done, total):
        try:
            self.progress.config(value=done)
        except Exception:
            pass
        self._set(f"جاري المسح…  {done}/{total}")

    def _render(self):
        self.list.clear()
        only = self.issues_var.get()
        shown = [d for d in self.devices if (d["flags"] or not only)]
        for i, d in enumerate(shown):
            self._card(d, i)

    def _card(self, d, idx):
        is_me = d.get("is_me")
        sev = self._severity(d["flags"])
        stripe = SKY if is_me else (RED if sev == 2 else (AMBER if sev == 1 else LINE))
        base = SURFACE if idx % 2 == 0 else SURFACE2

        row = tk.Frame(self.list.inner, bg=base)
        row.pack(fill="x", padx=6, pady=3)
        # شريط الحالة على اليمين (RTL)
        tk.Frame(row, bg=stripe, width=4).pack(side="right", fill="y")

        pad = tk.Frame(row, bg=base)
        pad.pack(fill="x", padx=14, pady=9)

        # السطر الأول: IP + الشركة (يمين) / الشارات (يسار)
        top = tk.Frame(pad, bg=base)
        top.pack(fill="x")

        ipcol = TEAL if is_me else TXT
        iptxt = d["ip"] + ("   جهازك" if is_me else "")
        tk.Label(top, text=iptxt, bg=base, fg=ipcol, font=(MONO, 13, "bold")).pack(side="right")

        chips = tk.Frame(top, bg=base)
        chips.pack(side="left")
        for fl in d["flags"]:
            cb, cf = CHIP.get(fl, (LINE, TXT))
            c = tk.Label(chips, text=fl, bg=cb, fg=cf, font=(UI, 8, "bold"),
                         padx=7, pady=1)
            c.pack(side="left", padx=3)

        # السطر الثاني: MAC + الاسم (يمين) / الشركة (يسار)
        bot = tk.Frame(pad, bg=base)
        bot.pack(fill="x", pady=(3, 0))
        meta = d["mac"]
        if d.get("name"):
            meta += "   ·   " + d["name"]
        tk.Label(bot, text=meta, bg=base, fg=MUT, font=(MONO, 9)).pack(side="right")
        vend = d.get("vendor") or "—"
        tk.Label(bot, text=vend, bg=base, fg=FAINT if vend == "—" else SKY,
                 font=(UI, 9)).pack(side="left")

    def _severity(self, flags):
        if any(f in ("IP متكرر", "MAC مكرر") for f in flags):
            return 2
        if flags:
            return 1
        return 0

    def _done(self):
        self.scanning = False
        self.scan_btn.config(text="▶  ابدأ المسح", bg=TEAL, activebackground=TEALDK)
        self._render()
        if self.devices:
            self.export_btn.config(state="normal", fg=TXT)
        issues = sum(1 for d in self.devices if d["flags"])
        self.stat_total.config(text=str(len(self.devices)))
        self.stat_issue.config(text=str(issues))
        if self.stop_flag.is_set():
            self._set(f"تم الإيقاف — {len(self.devices)} جهاز")
        else:
            try:
                self.progress.config(value=self.progress["maximum"])
            except Exception:
                pass
            self._set(f"اكتمل المسح ✓   {len(self.devices)} جهاز"
                      + (f"   ·   {issues} تنبيه" if issues else ""))

    def export(self):
        if not self.devices:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel", "*.xlsx"), ("CSV", "*.csv")],
            initialfile="الأجهزة.xlsx")
        if not path:
            return
        try:
            if path.lower().endswith(".xlsx"):
                if not scanner.export_xlsx(self.devices, path):
                    path = path[:-5] + ".csv"
                    scanner.export_csv(self.devices, path)
            else:
                scanner.export_csv(self.devices, path)
            messagebox.showinfo("تم", f"تم الحفظ في:\n{path}")
        except Exception as e:
            messagebox.showerror("خطأ", f"فشل التصدير:\n{e}")


def main():
    NetScanApp().mainloop()


if __name__ == "__main__":
    main()
