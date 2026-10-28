#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماسح أجهزة الشبكة — نسخة سطر الأوامر (نسخة 2).
تشتغل على الكمبيوتر (Windows/Linux/Mac) وعلى الموبايل (Termux).

التشغيل:
  python netscan.py                     # مسح تلقائي للشبكة
  python netscan.py --prefix 24         # تحديد حجم الشبكة
  python netscan.py --export devices.csv   # حفظ النتيجة CSV
  python netscan.py --export devices.xlsx  # حفظ النتيجة Excel
  python netscan.py --no-names          # أسرع، بدون أسماء الأجهزة
  python netscan.py --only-issues       # عرض الأجهزة اللي فيها مشاكل بس
"""

import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core import scanner
except Exception:
    sys.path.insert(0, os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core"))
    import scanner  # type: ignore


def main():
    ap = argparse.ArgumentParser(description="ماسح أجهزة الشبكة المحلية")
    ap.add_argument("--prefix", type=int, default=None,
                    help="حجم الشبكة (افتراضي: تلقائي)")
    ap.add_argument("--export", metavar="FILE",
                    help="حفظ النتيجة في ملف (.csv أو .xlsx)")
    ap.add_argument("--no-names", action="store_true", help="بدون أسماء الأجهزة")
    ap.add_argument("--no-vendor", action="store_true", help="بدون اسم الشركة")
    ap.add_argument("--only-issues", action="store_true",
                    help="عرض الأجهزة اللي فيها ملاحظات فقط")
    args = ap.parse_args()

    print("\n" + "=" * 74)
    print("   ماسح أجهزة الشبكة  —  netscan")
    print("=" * 74)

    local_ip, network = scanner.detect_network(args.prefix)
    if not network:
        print("\n  ⚠ مش لاقي شبكة. اتأكد إنك متصل.\n")
        return
    if network.num_addresses > scanner.MAX_ADDRESSES:
        print(f"\n  ⚠ الشبكة كبيرة جدًا ({network.num_addresses}). استخدم --prefix 24.\n")
        return

    print(f"\n  جهازك       : {local_ip}")
    print(f"  نطاق الشبكة  : {network}  ({network.num_addresses - 2} عنوان)")
    print("\n  جاري المسح…\n")

    def progress(done, total):
        pct = int(done * 100 / total) if total else 0
        bar = "█" * (pct // 4) + "░" * (25 - pct // 4)
        print(f"\r  [{bar}] {pct:3d}%  ({done}/{total})", end="", flush=True)

    devices = scanner.scan_network(
        network, progress_cb=progress,
        do_names=not args.no_names, do_vendor=not args.no_vendor)
    print("\n")

    shown = [d for d in devices if d["flags"]] if args.only_issues else devices

    if not shown:
        print("  لا توجد أجهزة لعرضها.\n")
    else:
        print("=" * 74)
        print(f"  عدد الأجهزة: {len(devices)}" +
              (f"  (المعروض: {len(shown)} بمشاكل)" if args.only_issues else ""))
        print("=" * 74)
        for d in shown:
            me = "  ← جهازك" if d["is_me"] else ""
            print(f"  {d['ip']:<16}{d['mac']:<20}{(d['vendor'] or '—')}{me}")
            extra = []
            if d["name"]:
                extra.append(f"الاسم: {d['name']}")
            if d["flags"]:
                extra.append("⚠ " + " / ".join(d["flags"]))
            if extra:
                print(f"       {'   '.join(extra)}")
        print("=" * 74)

    # ملخّص المشاكل
    issues = [d for d in devices if d["flags"]]
    if issues:
        print(f"\n  ⚠ تنبيه: {len(issues)} جهاز فيه ملاحظات (شوف العمود الأخير).")

    # التصدير
    if args.export:
        path = args.export
        try:
            if path.lower().endswith(".xlsx"):
                res = scanner.export_xlsx(devices, path)
                if not res:
                    path = path[:-5] + ".csv"
                    scanner.export_csv(devices, path)
                    print(f"\n  (openpyxl غير متوفرة — تم الحفظ CSV بدلًا منها)")
            else:
                scanner.export_csv(devices, path)
            print(f"\n  💾 تم الحفظ في: {os.path.abspath(path)}")
        except Exception as e:
            print(f"\n  ⚠ فشل التصدير: {e}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  تم الإيقاف.\n")
