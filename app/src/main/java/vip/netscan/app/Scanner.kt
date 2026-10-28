package vip.netscan.app

import android.content.Context
import android.net.ConnectivityManager
import java.io.BufferedReader
import java.io.FileReader
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

/** جهاز واحد على الشبكة. */
data class Device(
    val ip: String,
    val mac: String = "",
    val vendor: String = "",
    val name: String = "",
    val openPorts: List<Int> = emptyList(),
    val isSelf: Boolean = false,
    val flags: List<String> = emptyList()
)

/** نطاق الشبكة المكتشف تلقائيًا. */
data class NetInfo(val localIp: String, val prefix: Int, val hosts: List<String>)

object Scanner {

    /** منافذ شائعة: الاتصال بيها (أو رفضه) بيثبت إن الجهاز موجود. */
    private val PROBE_PORTS = intArrayOf(
        80, 443, 22, 445, 139, 8080, 53, 7547, 554, 8081, 9100, 62078
    )

    private const val MAX_HOSTS = 4096

    // ---------------------------------------------------------------- الشبكة

    /**
     * يكتشف عنوان الجهاز ونطاق الشبكة من الاتصال النشط — من غير ما المستخدم
     * يكتب أي IP. بيستخدم ConnectivityManager وده بيدّي الـ prefix الحقيقي.
     */
    fun detectNetwork(ctx: Context): NetInfo? {
        return try {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val net = cm.activeNetwork ?: return null
            val lp = cm.getLinkProperties(net) ?: return null
            for (la in lp.linkAddresses) {
                val a = la.address
                if (a is Inet4Address && !a.isLoopbackAddress) {
                    val ip = a.hostAddress ?: continue
                    val prefix = la.prefixLength
                    return NetInfo(ip, prefix, hostsOf(a, prefix))
                }
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    /** يطلّع كل العناوين الممكنة في الشبكة (من غير عنوان الشبكة والبث). */
    fun hostsOf(addr: Inet4Address, prefix: Int): List<String> {
        if (prefix < 8 || prefix > 32) return emptyList()
        var ipInt = 0
        for (b in addr.address) ipInt = (ipInt shl 8) or (b.toInt() and 0xFF)
        val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
        val network = ipInt and mask
        val broadcast = network or mask.inv()
        val out = ArrayList<String>()
        var h = network + 1
        while (h < broadcast && out.size < MAX_HOSTS) {
            out.add(intToIp(h))
            h++
        }
        return out
    }

    fun intToIp(v: Int): String =
        "${(v ushr 24) and 0xFF}.${(v ushr 16) and 0xFF}.${(v ushr 8) and 0xFF}.${v and 0xFF}"

    // ---------------------------------------------------------------- الفحص

    /**
     * يفحص عنوان واحد. بيرجّع (موجود، المنافذ المفتوحة).
     * الجهاز بيتحسب موجود لو رد على ping، أو فتح منفذ، أو **رفض** الاتصال —
     * لأن الرفض نفسه دليل إن في جهاز على العنوان ده.
     */
    private suspend fun probe(ip: String, pingMs: Int, portMs: Int): Pair<Boolean, List<Int>> =
        withContext(Dispatchers.IO) {
            var alive = false
            val open = ArrayList<Int>()

            try {
                if (InetAddress.getByName(ip).isReachable(pingMs)) alive = true
            } catch (e: Exception) {
                // الجهاز ممكن يحجب ping — بنكمّل على المنافذ
            }

            for (p in PROBE_PORTS) {
                try {
                    Socket().use { s ->
                        s.connect(InetSocketAddress(ip, p), portMs)
                        alive = true
                        open.add(p)
                    }
                } catch (e: Exception) {
                    val m = e.message ?: ""
                    if (m.contains("ECONNREFUSED", true) || m.contains("refused", true)) {
                        alive = true
                    }
                }
            }
            Pair(alive, open)
        }

    /**
     * يفحص الشبكة كلها بالتوازي.
     * onProgress(تم، الإجمالي) و onFound(جهاز) بيتنادوا أول بأول.
     */
    suspend fun scan(
        hosts: List<String>,
        localIp: String,
        parallel: Int = 64,
        onProgress: (Int, Int) -> Unit,
        onFound: (Device) -> Unit
    ) = coroutineScope {
        val sem = Semaphore(parallel)
        val total = hosts.size
        var done = 0
        val lock = Any()

        hosts.map { ip ->
            async(Dispatchers.IO) {
                sem.withPermit {
                    val (alive, ports) = probe(ip, 350, 220)
                    val n = synchronized(lock) { ++done }
                    onProgress(n, total)
                    if (alive) onFound(Device(ip = ip, openPorts = ports, isSelf = ip == localIp))
                }
            }
        }.awaitAll()
    }

    /** اسم الجهاز من الـ DNS العكسي (ممكن ميرجعش حاجة). */
    suspend fun resolveName(ip: String): String = withContext(Dispatchers.IO) {
        try {
            val n = InetAddress.getByName(ip).canonicalHostName
            if (n == ip) "" else n
        } catch (e: Exception) {
            ""
        }
    }

    // ------------------------------------------------------------------ MAC

    /**
     * يقرأ جدول ARP من النظام.
     * مهم: من أندرويد 10 وطالع، جوجل بتمنع التطبيقات العادية (من غير روت) من
     * قراءة /proc/net/arp، فده بيرجع فاضي على الموبايلات الحديثة — وساعتها
     * بنعرض العنوان والاسم من غير الـ MAC.
     */
    fun readArp(): Map<String, String> {
        val out = HashMap<String, String>()
        val macRe = Regex("^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
        try {
            BufferedReader(FileReader("/proc/net/arp")).use { r ->
                r.readLine() // سطر العناوين
                while (true) {
                    val line = r.readLine() ?: break
                    val p = line.trim().split(Regex("\\s+"))
                    if (p.size >= 4) {
                        val ip = p[0]
                        val mac = p[3].lowercase()
                        if (macRe.matches(mac) && mac != "00:00:00:00:00:00") out[ip] = mac
                    }
                }
            }
        } catch (e: Exception) {
            // متوقع على أندرويد الحديث
        }
        return out
    }

    /** العنوان العشوائي/المحلي: البت الثاني في أول خانة (خاصية الخصوصية). */
    fun isRandomMac(mac: String): Boolean = try {
        (mac.substring(0, 2).toInt(16) and 0x02) != 0
    } catch (e: Exception) {
        false
    }

    // -------------------------------------------------------------- الملاحظات

    /**
     * يكشف المشاكل على الشبكة:
     *  - IP متكرر   : نفس العنوان رد بأكتر من MAC
     *  - MAC مكرر   : نفس الـ MAC على أكتر من عنوان
     *  - MAC متشابه : ماكات بتختلف في آخر خانة بس (نفس الجهاز بأكتر من كارت)
     *  - MAC عشوائي : عنوان خصوصية
     */
    fun analyze(devices: List<Device>): List<Device> {
        val byMac = HashMap<String, MutableSet<String>>()
        val byIp = HashMap<String, MutableSet<String>>()
        val byPrefix = HashMap<String, MutableSet<String>>()

        for (d in devices) {
            if (d.mac.isNotEmpty()) {
                byMac.getOrPut(d.mac) { HashSet() }.add(d.ip)
                if (d.mac.length == 17) {
                    byPrefix.getOrPut(d.mac.substring(0, 14)) { HashSet() }.add(d.mac)
                }
                byIp.getOrPut(d.ip) { HashSet() }.add(d.mac)
            }
        }

        return devices.map { d ->
            val f = ArrayList<String>()
            if (d.mac.isNotEmpty()) {
                if ((byIp[d.ip]?.size ?: 0) > 1) f.add("IP متكرر")
                if ((byMac[d.mac]?.size ?: 0) > 1) f.add("MAC مكرر")
                if ((byPrefix[d.mac.substring(0, 14)]?.size ?: 0) > 1) f.add("MAC متشابه")
                if (isRandomMac(d.mac)) f.add("MAC عشوائي")
            }
            d.copy(flags = f)
        }
    }
}
