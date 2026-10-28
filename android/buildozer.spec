[app]
title = NetScan
package.name = netscan
package.domain = org.mohamed.netscan
source.dir = .
source.include_exts = py,ttf,gz
version = 1.0

# المكتبات المطلوبة لبناء التطبيق
requirements = python3,kivy==2.3.1,arabic_reshaper==3.0.0,python-bidi==0.4.2

orientation = portrait
fullscreen = 0

# الصلاحيات: الوصول للشبكة وحالة الواي فاي
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE

# إعدادات SDK/NDK (نسخ مستقرة مع buildozer)
android.api = 33
android.minapi = 21
android.ndk = 25b
android.archs = arm64-v8a,armeabi-v7a
android.accept_sdk_license = True

# أيقونة افتراضية (Kivy بيحط أيقونة تلقائية لو مش محددة)
# icon.filename = %(source.dir)s/icon.png

[buildozer]
log_level = 2
warn_on_root = 0
