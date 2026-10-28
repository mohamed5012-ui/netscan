# -*- coding: utf-8 -*-
"""
نقطة البداية (bootstrap) — تستدعي التطبيق الحقيقي (app_main) داخل حماية.
أي خطأ في بايثون — حتى وقت الاستيراد — يتكتب في ملف ويتعرض على الشاشة
بالخط الافتراضي بدل ما التطبيق يقفل فجأة.
"""

import os
import traceback


def _dump(text):
    for p in ("/sdcard/Download/netscan_error.txt",
              "/storage/emulated/0/Download/netscan_error.txt",
              os.path.join(os.path.dirname(os.path.abspath(__file__)), "netscan_error.txt")):
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
            break
        except Exception:
            continue


def _show_error(tb):
    """يعرض نص الخطأ على الشاشة بالخط الافتراضي (عشان شاشة الخطأ نفسها ما تضربش)."""
    try:
        from kivy.app import App
        from kivy.uix.scrollview import ScrollView
        from kivy.uix.label import Label
        from kivy.core.window import Window
        Window.clearcolor = (0.05, 0.05, 0.08, 1)

        class ErrApp(App):
            def build(self):
                sv = ScrollView()
                lbl = Label(text="❌ خطأ عند بدء التشغيل:\n\n" + tb,
                            halign="left", valign="top", font_size="12sp",
                            color=(1, 0.75, 0.75, 1), size_hint_y=None,
                            padding=(14, 14))

                def _fit(*a):
                    lbl.text_size = (lbl.width - 28, None)
                    lbl.height = lbl.texture_size[1] + 28
                lbl.bind(width=_fit, texture_size=_fit)
                sv.add_widget(lbl)
                return sv
        ErrApp().run()
    except Exception:
        pass


def main():
    try:
        import app_main
        app_main.main()
    except Exception:
        tb = traceback.format_exc()
        _dump(tb)
        _show_error(tb)


if __name__ == "__main__":
    main()
