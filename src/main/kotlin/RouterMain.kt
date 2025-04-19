package org.bread_experts_group

import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.logging.Logger


fun main(args: Array<String>) {
	val logger = Logger.getLogger("HTTP Routing, Main")
	Thread.currentThread().name = "Routing-Main"
	logger.fine("- Argument read")
	val (singleArgs, multipleArgs) = readArgs(
		args,
		Flag<String>("keystore"),
		Flag<String>("keystore_passphrase"),
		Flag<String>("ip"),
		Flag<Int>("port", default = 443, conv = ::stringToInt),
		Flag<Int>("port_insecure", default = 80, conv = ::stringToInt),
		Flag<String>("route", repeatable = true),
		Flag<String>("redirect", repeatable = true)
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
	val tlsSocket = getTLSContext(
		File(singleArgs.getValue("keystore") as String),
		singleArgs.getValue("keystore_passphrase") as String,
	)
	val secureServerSocket = tlsSocket.getServerSocket()
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
	val routingTable = buildMap {
		multipleArgs.getValue("route").forEach { routingDescriptor ->
			val (host, targetPort) = (routingDescriptor as String).split(',')
			this[host] = targetPort.toInt()
		}
	}
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