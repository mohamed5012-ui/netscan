package vip.netscan.app

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.runtime.CompositionLocalProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

// ============================ الألوان (نفس تصميم نسخة الويندوز) ============================
private val BG = Color(0xFF0A0E14)
private val SURFACE = Color(0xFF121A24)
private val SURFACE2 = Color(0xFF0F1620)
private val LINE = Color(0xFF1E2A38)
private val TEAL = Color(0xFF2DD4BF)
private val SKY = Color(0xFF38BDF8)
private val REDC = Color(0xFFF87171)
private val AMBER = Color(0xFFFBBF24)
private val TXT = Color(0xFFE8EEF2)
private val MUT = Color(0xFF7D8B99)

private fun chipColors(flag: String): Pair<Color, Color> = when (flag) {
    "IP متكرر" -> Color(0xFF7F1D1D) to Color(0xFFFECACA)
    "MAC مكرر" -> Color(0xFF7C2D12) to Color(0xFFFED7AA)
    "MAC متشابه" -> Color(0xFF713F12) to Color(0xFFFDE68A)
    else -> Color(0xFF334155) to Color(0xFFCBD5E1)
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = TEAL,
                    background = BG,
                    surface = SURFACE,
                    onPrimary = Color(0xFF04131A),
                    onBackground = TXT,
                    onSurface = TXT
                )
            ) {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                    NetScanScreen()
                }
            }
        }
    }
}

@Composable
private fun NetScanScreen() {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()

    val devices: SnapshotStateList<Device> = remember { mutableStateListOf() }
    var status by remember { mutableStateOf("جاري اكتشاف الشبكة…") }
    var netLabel by remember { mutableStateOf("—") }
    var scanning by remember { mutableStateOf(false) }
    var doneCount by remember { mutableIntStateOf(0) }
    var totalCount by remember { mutableIntStateOf(0) }
    var job by remember { mutableStateOf<Job?>(null) }

    // اكتشاف الشبكة أول ما الشاشة تفتح
    LaunchedEffect(Unit) {
        val info = withContext(Dispatchers.IO) { Scanner.detectNetwork(ctx) }
        if (info == null) {
            status = "مش لاقي شبكة — اتأكد إنك متصل بالواي فاي"
            netLabel = "—"
        } else {
            netLabel = "${info.localIp}/${info.prefix}"
            totalCount = info.hosts.size
            status = "جاهز · ${info.hosts.size} عنوان في الشبكة"
        }
    }

    fun startScan() {
        if (scanning) {
            job?.cancel()
            scanning = false
            status = "تم الإيقاف — ${devices.size} جهاز"
            return
        }
        job = scope.launch {
            scanning = true
            devices.clear()
            doneCount = 0
            status = "جاري المسح…"

            val info = withContext(Dispatchers.IO) { Scanner.detectNetwork(ctx) }
            if (info == null) {
                status = "مش لاقي شبكة"
                scanning = false
                return@launch
            }
            netLabel = "${info.localIp}/${info.prefix}"
            totalCount = info.hosts.size

            val found = java.util.Collections.synchronizedList(ArrayList<Device>())
            withContext(Dispatchers.IO) {
                Scanner.scan(
                    hosts = info.hosts,
                    localIp = info.localIp,
                    onProgress = { d, _ -> doneCount = d },
                    onFound = { dev -> found.add(dev) }
                )
            }

            // إثراء النتائج: MAC (لو متاح) + الشركة + الاسم
            val enriched = withContext(Dispatchers.IO) {
                val arp = Scanner.readArp()
                val db = Vendors.load(ctx)
                val list = found.toList().sortedBy { ipKey(it.ip) }.map { d ->
                    val mac = arp[d.ip] ?: ""
                    d.copy(
                        mac = mac,
                        vendor = if (mac.isNotEmpty()) Vendors.of(mac, db) else "",
                        name = Scanner.resolveName(d.ip)
                    )
                }
                Scanner.analyze(list)
            }

            devices.clear()
            devices.addAll(enriched)
            doneCount = totalCount
            val issues = enriched.count { it.flags.isNotEmpty() }
            status = "اكتمل المسح ✓ · ${enriched.size} جهاز" +
                if (issues > 0) " · $issues تنبيه" else ""
            scanning = false
        }
    }

    fun export() {
        scope.launch {
            val path = withContext(Dispatchers.IO) { writeCsv(ctx, devices.toList()) }
            status = if (path != null) "تم الحفظ: $path" else "تعذّر حفظ الملف"
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BG)
            .padding(horizontal = 16.dp)
    ) {
        Spacer(Modifier.height(18.dp))

        // ===== الهيدر =====
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("ماسح أجهزة الشبكة", color = TXT, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(2.dp))
                Text("NETSCAN · مراقبة الأجهزة المتصلة", color = TEAL, fontSize = 11.sp)
            }
            Box(
                Modifier
                    .size(34.dp)
                    .background(TEAL.copy(alpha = 0.15f), RoundedCornerShape(17.dp)),
                contentAlignment = Alignment.Center
            ) { Text("◎", color = TEAL, fontSize = 18.sp) }
        }

        Spacer(Modifier.height(14.dp))
        Box(Modifier.fillMaxWidth().height(1.dp).background(LINE))
        Spacer(Modifier.height(14.dp))

        // ===== صف التحكم =====
        Row(verticalAlignment = Alignment.CenterVertically) {
            Button(
                onClick = { startScan() },
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (scanning) REDC else TEAL,
                    contentColor = Color(0xFF04131A)
                ),
                shape = RoundedCornerShape(10.dp)
            ) {
                Text(
                    if (scanning) "إيقاف" else "ابدأ المسح",
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp
                )
            }

            Spacer(Modifier.width(8.dp))

            Button(
                onClick = { export() },
                enabled = devices.isNotEmpty() && !scanning,
                colors = ButtonDefaults.buttonColors(
                    containerColor = SURFACE,
                    contentColor = TXT,
                    disabledContainerColor = SURFACE2,
                    disabledContentColor = MUT
                ),
                shape = RoundedCornerShape(10.dp)
            ) { Text("تصدير", fontSize = 13.sp) }

            Spacer(Modifier.weight(1f))

            Column(horizontalAlignment = Alignment.End) {
                Text("الشبكة", color = MUT, fontSize = 10.sp)
                Text(netLabel, color = TEAL, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
            }
        }

        Spacer(Modifier.height(12.dp))

        // ===== شريط التقدم =====
        val pct = if (totalCount > 0) doneCount.toFloat() / totalCount else 0f
        LinearProgressIndicator(
            progress = { pct },
            modifier = Modifier.fillMaxWidth().height(6.dp),
            color = TEAL,
            trackColor = SURFACE2
        )

        Spacer(Modifier.height(8.dp))
        Text(status, color = MUT, fontSize = 12.sp)
        Spacer(Modifier.height(10.dp))

        // ===== قائمة الأجهزة =====
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            items(devices) { d -> DeviceCard(d) }
        }
    }
}

@Composable
private fun DeviceCard(d: Device) {
    val severe = d.flags.any { it == "IP متكرر" || it == "MAC مكرر" }
    val stripe = when {
        d.isSelf -> SKY
        severe -> REDC
        d.flags.isNotEmpty() -> AMBER
        else -> LINE
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = SURFACE),
        shape = RoundedCornerShape(8.dp)
    ) {
        Row(Modifier.fillMaxWidth()) {
            Box(Modifier.width(4.dp).height(64.dp).background(stripe))
            Column(Modifier.padding(horizontal = 12.dp, vertical = 10.dp).weight(1f)) {

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        d.ip,
                        color = if (d.isSelf) TEAL else TXT,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                    if (d.isSelf) {
                        Spacer(Modifier.width(8.dp))
                        Text("جهازك", color = SKY, fontSize = 11.sp)
                    }
                    Spacer(Modifier.weight(1f))
                    if (d.vendor.isNotEmpty()) {
                        Text(d.vendor, color = SKY, fontSize = 11.sp, maxLines = 1)
                    }
                }

                Spacer(Modifier.height(3.dp))

                val meta = buildString {
                    append(if (d.mac.isNotEmpty()) d.mac else "MAC غير متاح")
                    if (d.name.isNotEmpty()) append("  ·  ").append(d.name)
                    if (d.openPorts.isNotEmpty()) {
                        append("  ·  منافذ: ").append(d.openPorts.joinToString(","))
                    }
                }
                Text(meta, color = MUT, fontSize = 11.sp, fontFamily = FontFamily.Monospace, maxLines = 2)

                if (d.flags.isNotEmpty()) {
                    Spacer(Modifier.height(5.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                        d.flags.forEach { f ->
                            val (bg, fg) = chipColors(f)
                            Box(
                                Modifier
                                    .background(bg, RoundedCornerShape(4.dp))
                                    .padding(horizontal = 7.dp, vertical = 2.dp)
                            ) { Text(f, color = fg, fontSize = 9.sp, fontWeight = FontWeight.Bold) }
                        }
                    }
                }
            }
        }
    }
}

// ============================ أدوات ============================

private fun ipKey(ip: String): Long = try {
    ip.split(".").fold(0L) { acc, p -> (acc shl 8) or p.toLong() }
} catch (e: Exception) {
    0L
}

/** يحفظ النتائج في ملف CSV ويرجّع مساره. */
private fun writeCsv(ctx: Context, devices: List<Device>): String? = try {
    val dir = ctx.getExternalFilesDir(null) ?: ctx.filesDir
    val f = File(dir, "netscan_devices.csv")
    f.bufferedWriter(Charsets.UTF_8).use { w ->
        w.write("﻿") // عشان Excel يقرأ العربي صح
        w.write("IP,MAC,الشركة,اسم الجهاز,المنافذ,ملاحظات\n")
        for (d in devices) {
            w.write(
                listOf(
                    d.ip,
                    d.mac,
                    d.vendor,
                    d.name,
                    d.openPorts.joinToString(" "),
                    d.flags.joinToString(" / ")
                ).joinToString(",") { it.replace(",", " ") }
            )
            w.write("\n")
        }
    }
    f.absolutePath
} catch (e: Exception) {
    null
}
