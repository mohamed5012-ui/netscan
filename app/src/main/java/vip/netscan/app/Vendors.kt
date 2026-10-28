package vip.netscan.app

import android.content.Context
import java.util.zip.GZIPInputStream

/**
 * قاعدة بيانات الشركات المصنّعة (أكتر من 59 ألف بادئة MAC).
 * الملف مضغوط جوه التطبيق وبيتقرأ مرة واحدة عند أول استخدام.
 */
object Vendors {

    @Volatile
    private var cache: Map<String, String>? = null

    fun load(ctx: Context): Map<String, String> {
        cache?.let { return it }
        val m = HashMap<String, String>(70_000)
        try {
            ctx.resources.openRawResource(R.raw.vendors).use { raw ->
                GZIPInputStream(raw).bufferedReader().forEachLine { line ->
                    val t = line.indexOf('\t')
                    if (t > 0) {
                        val key = line.substring(0, t).uppercase()
                        val name = line.substring(t + 1).trim()
                        if (name.isNotEmpty()) m[key] = name
                    }
                }
            }
        } catch (e: Exception) {
            // لو حصل أي مشكلة في القراءة، بنكمّل من غير أسماء شركات
        }
        cache = m
        return m
    }

    /** بيدوّر بأطول مطابقة: /36 ثم /28 ثم /24. */
    fun of(mac: String, db: Map<String, String>): String {
        if (mac.length < 8) return ""
        val hex = mac.uppercase().replace(":", "")
        for (n in intArrayOf(9, 7, 6)) {
            if (hex.length >= n) db[hex.substring(0, n)]?.let { return it }
        }
        return ""
    }
}
