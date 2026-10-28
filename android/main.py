# -*- coding: utf-8 -*-
"""نسخة تشخيص بسيطة: تختبر إن Kivy بيشتغل أصلاً على الجهاز."""
import os, traceback

def _dump(t):
    for p in ("/sdcard/Download/netscan_error.txt",
              "/storage/emulated/0/Download/netscan_error.txt"):
        try:
            open(p, "w", encoding="utf-8").write(t); break
        except Exception:
            continue

try:
    from kivy.app import App
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.label import Label
    from kivy.uix.button import Button

    class Diag(App):
        def build(self):
            root = BoxLayout(orientation="vertical", padding=24, spacing=24)
            root.add_widget(Label(
                text="NetScan diagnostic\nKivy is working.",
                halign="center"))
            self.lbl = Label(text="tap TEST")
            root.add_widget(self.lbl)
            b = Button(text="TEST", size_hint_y=0.3)
            b.bind(on_release=self.go)
            root.add_widget(b)
            return root

        def go(self, *a):
            self.lbl.text = "button works!"

    def main():
        Diag().run()
except Exception:
    _dump(traceback.format_exc())
    raise

if __name__ == "__main__":
    main()
