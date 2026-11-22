package com.follow.clash.service

import android.content.Context
import android.content.pm.PackageManager
import android.os.Process
import com.follow.clash.common.AccessControlMode
import com.follow.clash.common.GlobalState
import com.follow.clash.service.models.VpnOptions
import java.util.concurrent.TimeUnit

internal object RootProxyController {
    private const val REDIR_PORT = 7892
    private const val DNS_PORT = 1053
    private const val CHAIN_OUT = "FLCLASH_OUT"
    private const val CHAIN_PRE = "FLCLASH_PRE"
    private const val WATCHDOG_PID_FILE = "/data/local/tmp/flclash_root_watchdog.pid"

    private val bypassCidrs = listOf(
        "0.0.0.0/8",
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )

    @Volatile
    private var rootRulesActive = false

    fun applyKeepAliveIfRoot(context: Context) {
        if (!isRootAvailable()) return
        runSu(buildKeepAliveScript(context.packageName, Process.myPid()))
    }

    fun startRootProxy(context: Context, options: VpnOptions?) {
        if (!isRootAvailable()) {
            GlobalState.log("Root not available; running local proxy without kernel redirect")
            return
        }
        val pkg = context.packageName
        val myUid = Process.myUid()
        val myPid = Process.myPid()
        val accessControl = options?.accessControlProps
        val excludedUids = mutableSetOf<Int>()
        val allowedUids = mutableSetOf<Int>()

        if (accessControl != null && accessControl.enable) {
            when (accessControl.mode) {
                AccessControlMode.REJECT_SELECTED -> {
                    accessControl.rejectList.forEach { name ->
                        resolveUid(context.packageManager, name)?.let { excludedUids.add(it) }
                    }
                }

                AccessControlMode.ACCEPT_SELECTED -> {
                    accessControl.acceptList.forEach { name ->
                        resolveUid(context.packageManager, name)?.let { allowedUids.add(it) }
                    }
                }
            }
        }

        val script = buildString {
            appendLine(buildKeepAliveScript(pkg, myPid))
            appendLine(buildCleanupScript())
            appendLine("IPT=\"iptables -w\"")
            appendLine("\$IPT -t nat -N $CHAIN_OUT 2>/dev/null || \$IPT -t nat -F $CHAIN_OUT")
            appendLine("\$IPT -t nat -A $CHAIN_OUT -m owner --uid-owner $myUid -j RETURN")
            bypassCidrs.forEach { cidr ->
                appendLine("\$IPT -t nat -A $CHAIN_OUT -d $cidr -j RETURN")
            }

            if (accessControl != null && accessControl.enable && accessControl.mode == AccessControlMode.ACCEPT_SELECTED) {
                allowedUids.filter { it != myUid }.forEach { uid ->
                    appendLine("\$IPT -t nat -A $CHAIN_OUT -p udp --dport 53 -m owner --uid-owner $uid -j REDIRECT --to-ports $DNS_PORT")
                    appendLine("\$IPT -t nat -A $CHAIN_OUT -p tcp --dport 53 -m owner --uid-owner $uid -j REDIRECT --to-ports $DNS_PORT")
                    appendLine("\$IPT -t nat -A $CHAIN_OUT -p tcp -m owner --uid-owner $uid -j REDIRECT --to-ports $REDIR_PORT")
                }
            } else {
                excludedUids.filter { it != myUid }.forEach { uid ->
                    appendLine("\$IPT -t nat -A $CHAIN_OUT -m owner --uid-owner $uid -j RETURN")
                }
                appendLine("\$IPT -t nat -A $CHAIN_OUT -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT")
                appendLine("\$IPT -t nat -A $CHAIN_OUT -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT")
                appendLine("\$IPT -t nat -A $CHAIN_OUT -p tcp -j REDIRECT --to-ports $REDIR_PORT")
            }

            appendLine("\$IPT -t nat -I OUTPUT 1 -j $CHAIN_OUT")

            appendLine("\$IPT -t nat -N $CHAIN_PRE 2>/dev/null || \$IPT -t nat -F $CHAIN_PRE")
            bypassCidrs.forEach { cidr ->
                appendLine("\$IPT -t nat -A $CHAIN_PRE -d $cidr -j RETURN")
            }
            appendLine("\$IPT -t nat -A $CHAIN_PRE -p udp --dport 53 -j REDIRECT --to-ports $DNS_PORT")
            appendLine("\$IPT -t nat -A $CHAIN_PRE -p tcp --dport 53 -j REDIRECT --to-ports $DNS_PORT")
            appendLine("\$IPT -t nat -A $CHAIN_PRE -p tcp -j REDIRECT --to-ports $REDIR_PORT")
            appendLine("\$IPT -t nat -I PREROUTING 1 -j $CHAIN_PRE")

            appendLine(buildWatchdogScript(myPid))
        }

        if (runSu(script)) {
            rootRulesActive = true
            GlobalState.log("Root kernel transparent proxy started (redir=$REDIR_PORT, dns=$DNS_PORT)")
        } else {
            GlobalState.log("Failed to apply root iptables rules")
        }
    }

    fun stopRootProxy() {
        if (!rootRulesActive) return
        rootRulesActive = false
        runSu(buildCleanupScript())
        GlobalState.log("Root kernel transparent proxy stopped")
    }

    private fun buildKeepAliveScript(pkg: String, myPid: Int): String = buildString {
        appendLine("dumpsys deviceidle whitelist +$pkg >/dev/null 2>&1 || true")
        appendLine("cmd appops set $pkg RUN_IN_BACKGROUND allow >/dev/null 2>&1 || true")
        appendLine("cmd appops set $pkg RUN_ANY_IN_BACKGROUND allow >/dev/null 2>&1 || true")
        appendLine("am set-standby-bucket $pkg active >/dev/null 2>&1 || true")
        appendLine("echo -1000 > /proc/$myPid/oom_score_adj 2>/dev/null || true")
        appendLine("for p in \$(pidof $pkg 2>/dev/null); do echo -1000 > /proc/\$p/oom_score_adj 2>/dev/null || true; done")
    }

    private fun buildCleanupScript(): String = buildString {
        appendLine("if [ -f $WATCHDOG_PID_FILE ]; then kill \$(cat $WATCHDOG_PID_FILE) 2>/dev/null || true; rm -f $WATCHDOG_PID_FILE; fi")
        appendLine("IPT=\"iptables -w\"")
        appendLine("while \$IPT -t nat -D OUTPUT -j $CHAIN_OUT 2>/dev/null; do :; done")
        appendLine("\$IPT -t nat -F $CHAIN_OUT 2>/dev/null || true")
        appendLine("\$IPT -t nat -X $CHAIN_OUT 2>/dev/null || true")
        appendLine("while \$IPT -t nat -D PREROUTING -j $CHAIN_PRE 2>/dev/null; do :; done")
        appendLine("\$IPT -t nat -F $CHAIN_PRE 2>/dev/null || true")
        appendLine("\$IPT -t nat -X $CHAIN_PRE 2>/dev/null || true")
    }

    private fun buildWatchdogScript(myPid: Int): String =
        """
        (
          while [ -d /proc/$myPid ]; do
            echo -1000 > /proc/$myPid/oom_score_adj 2>/dev/null || true
            sleep 5
          done
          IPT="iptables -w"
          while ${'$'}IPT -t nat -D OUTPUT -j $CHAIN_OUT 2>/dev/null; do :; done
          ${'$'}IPT -t nat -F $CHAIN_OUT 2>/dev/null || true
          ${'$'}IPT -t nat -X $CHAIN_OUT 2>/dev/null || true
          while ${'$'}IPT -t nat -D PREROUTING -j $CHAIN_PRE 2>/dev/null; do :; done
          ${'$'}IPT -t nat -F $CHAIN_PRE 2>/dev/null || true
          ${'$'}IPT -t nat -X $CHAIN_PRE 2>/dev/null || true
          rm -f $WATCHDOG_PID_FILE
        ) </dev/null >/dev/null 2>&1 &
        echo ${'$'}! > $WATCHDOG_PID_FILE
        """.trimIndent()

    private fun resolveUid(pm: PackageManager, pkg: String): Int? = try {
        @Suppress("DEPRECATION")
        pm.getApplicationInfo(pkg, 0).uid
    } catch (_: Exception) {
        null
    }

    private fun isRootAvailable(): Boolean = try {
        val process = ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        val finished = process.waitFor(3, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            false
        } else {
            process.exitValue() == 0 && output.contains("uid=0")
        }
    } catch (_: Exception) {
        false
    }

    private fun runSu(script: String): Boolean = try {
        val process = ProcessBuilder("su", "-c", "sh").redirectErrorStream(true).start()
        process.outputStream.bufferedWriter().use { writer ->
            writer.write(script)
            writer.newLine()
            writer.write("exit 0")
            writer.newLine()
        }
        val finished = process.waitFor(8, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            false
        } else {
            process.exitValue() == 0
        }
    } catch (_: Exception) {
        false
    }
}
