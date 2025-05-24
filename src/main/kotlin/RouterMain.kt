package org.bread_experts_group.http_router

import org.bread_experts_group.Flag
import org.bread_experts_group.getServerSocket
import org.bread_experts_group.getTLSContext
import org.bread_experts_group.goodSchemes
import org.bread_experts_group.logging.ColoredLogger
import org.bread_experts_group.readArgs
import org.bread_experts_group.stringToInt
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIMatcher
import javax.net.ssl.SNIServerName
import javax.net.ssl.StandardConstants

fun main(args: Array<String>) {
	val logger = ColoredLogger.newLogger("HTTP Routing, Main")
	Thread.currentThread().name = "Routing-Main"
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
	val tlsSocket = getTLSContext(
		File(singleArgs.getValue("keystore") as String),
		singleArgs.getValue("keystore_passphrase") as String,
	)
	val secureServerSocket = tlsSocket.getServerSocket()
	val parameters = secureServerSocket.sslParameters
	val routingTable = buildMap {
		multipleArgs.getValue("route").forEach { routingDescriptor ->
			val (host, targetPort) = (routingDescriptor as String).split(',')
			this[host] = targetPort.toInt()
		}
	}
	parameters.applicationProtocols = arrayOf("http/1.1")
	parameters.sniMatchers = listOf(
		object : SNIMatcher(StandardConstants.SNI_HOST_NAME) {
			override fun matches(serverName: SNIServerName): Boolean =
				(serverName as SNIHostName).asciiName in routingTable.keys
		}
	)
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