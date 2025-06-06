package org.bread_experts_group.http_router

import org.bread_experts_group.Flag
import org.bread_experts_group.getServerSocket
import org.bread_experts_group.getTLSContext
import org.bread_experts_group.goodSchemes
import org.bread_experts_group.logging.ColoredLogger
import org.bread_experts_group.readArgs
import org.bread_experts_group.stringToInt
import org.bread_experts_group.truncateSI
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.ConcurrentHashMap

val connectionStats = ConcurrentHashMap<String, ConnectionStats>()

fun main(args: Array<String>) {
	val logger = ColoredLogger.newLogger("Routing")
	Runtime.getRuntime().addShutdownHook(Thread.ofPlatform().unstarted {
		println("=== Router Stats ===")
		var totalRx = 0L
		var totalTx = 0L
		var totalConnections = 0L
		connectionStats.forEach { (ipAddr, stats) ->
			totalRx += stats.rx
			totalTx += stats.tx
			totalConnections += stats.connections
			val localStat = buildString {
				appendLine(ipAddr)
				appendLine("- Received   : ${truncateSI(stats.rx)}B")
				appendLine("- Sent       : ${truncateSI(stats.tx)}B")
				appendLine("- Connections: ${stats.connections}")
			}
			print(localStat)
		}
		println("Total received   : ${truncateSI(totalRx)}B")
		println("Total sent       : ${truncateSI(totalTx)}B")
		println("Total connections: $totalConnections")
		ColoredLogger.flush()
	})

	Thread.currentThread().name = "Routing Main"
	logger.fine("- Argument read")
	val (singleArgs, multipleArgs) = readArgs(
		args,
		"http_router",
		"Distribution of software for Bread Experts Group operated port/shared file routing servers.",
		Flag<String>(
			"keystore", "The PKCS #12  keystore on which SSL/TLS requests will be encrypted via.",
			required = 1
		),
		Flag<String>(
			"keystore_passphrase", "The PKCS #12 keystore passphrase.",
			required = 1
		),
		Flag("ip", "The IP address on which to listen to.", default = "0.0.0.0"),
		Flag("port", "The TCP port on which to listen to for SSL/TLS requests.", default = 443, conv = ::stringToInt),
		Flag(
			"port_insecure", "The TCP port on which to listen to for plaintext requests.",
			default = 80, conv = ::stringToInt
		),
		Flag<String>(
			"route", "A route on which to direct requests towards, specified by the Host header.",
			repeatable = true
		),
		Flag<String>(
			"redirect", "A route on which to redirect requests to another server, specified by the Host header.",
			repeatable = true
		)
	)
	logger.fine("- Insecure socket retrieval")
	val insecureServerSocket = ServerSocket()
	logger.fine { "- Insecure socket (${singleArgs["port_insecure"]}) bind" }
	insecureServerSocket.bind(
		InetSocketAddress(
			(singleArgs["ip"] as? String) ?: "0.0.0.0",
			singleArgs["port_insecure"] as Int
		),
	)
	logger.fine("- TLS context and secure socket retrieval")
	val tlsContext = getTLSContext(
		File(singleArgs.getValue("keystore") as String),
		singleArgs.getValue("keystore_passphrase") as String,
	)
	val secureServerSocket = tlsContext.getServerSocket()
	val parameters = secureServerSocket.sslParameters
	val routingTable = buildMap {
		multipleArgs.getValue("route").forEach { routingDescriptor ->
			val (host, targetPort) = (routingDescriptor as String).split(',')
			this[host] = targetPort.toInt()
		}
	}
	parameters.applicationProtocols = arrayOf("http/1.1")
	parameters.useCipherSuitesOrder = true
	secureServerSocket.sslParameters = parameters
	secureServerSocket.enabledCipherSuites = goodSchemes
	secureServerSocket.wantClientAuth = true
	logger.fine("- Secure socket (${singleArgs["port"]}) bind")
	secureServerSocket.bind(
		InetSocketAddress(
			(singleArgs["ip"] as? String) ?: "0.0.0.0",
			singleArgs["port"] as Int
		),
	)
	logger.info("- Server loop (${secureServerSocket.localSocketAddress}, ${insecureServerSocket.localSocketAddress})")
	val redirectionTable = buildMap {
		multipleArgs["redirect"]?.forEach { redirectionDescriptor ->
			val (host, targetURI, permanent) = (redirectionDescriptor as String).split(',')
			this[host] = targetURI to permanent.toBooleanStrict()
		}
	}
	Thread.ofPlatform().name("Routing-Secure").start(
		secureOperation(secureServerSocket, routingTable, redirectionTable)
	)
	Thread.ofPlatform().name("Routing-Insecure").start(
		insecureOperation(insecureServerSocket)
	)
}