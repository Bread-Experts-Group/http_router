package org.bread_experts_group.http_router

import org.bread_experts_group.command_line.ArgumentContainer
import org.bread_experts_group.command_line.Flag
import org.bread_experts_group.command_line.readArgs
import org.bread_experts_group.command_line.stringToInt
import org.bread_experts_group.logging.ColoredHandler
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ProtocolFamily
import java.net.StandardProtocolFamily
import java.nio.channels.ServerSocketChannel

// TODO: Save to file / log
val connectionStats = mutableMapOf<String, ConnectionStats>()

val ipFlag = Flag(
	"ips",
	"The IP addresses on which to listen to.\nFormat: addr4,addr6",
	default = InetAddress.getLocalHost() to InetAddress.getLocalHost(),
	conv = {
		val (insecure, secure) = it
			.split(',')
			.also { i -> if (i.size != 2) throw IllegalArgumentException("There must be 2 IPs; got [${i.size}]") }
			.map { addr -> if (addr.isEmpty()) null else InetAddress.getByName(addr) }
		insecure to secure
	}
)
val portFlag = Flag(
	"ports", "The TCP ports on which to listen to.\nFormat: portHttp,portHttps",
	default = 80 to 443,
	conv = {
		val selector = stringToInt(0..65535)
		val (insecure, secure) = it
			.split(',')
			.also { p -> if (p.size != 2) throw IllegalArgumentException("There must be 2 ports; got [${p.size}]") }
			.map { port -> if (port.isEmpty()) null else selector.invoke(port) }
		insecure to secure
	}
)

fun main(args: Array<String>) {
	val logger = ColoredHandler.newLogger("Routing")
	Thread.currentThread().name = "Routing Main"
	logger.fine("- Argument read")
	val arguments = readArgs(
		args,
		"http_router",
		"Distribution of software for Bread Experts Group operated port/shared file routing servers.",
		Flag(
			"keystore", "The PKCS #12  keystore on which SSL/TLS requests will be encrypted via.",
			required = 1, conv = ::File
		),
		Flag<String>(
			"keystore_passphrase", "The PKCS #12 keystore passphrase.",
			required = 1
		),
		ipFlag,
		portFlag,
		Flag<String>(
			"route",
			"A route on which to direct requests towards, specified by the Host header (or SNI.)",
			repeatable = true
		),
		Flag<String>(
			"redirect",
			"A route on which to redirect requests to another server, specified by the Host header (or SNI.)",
			repeatable = true
		)
	)

	val routingTable = buildMap {
		arguments.gets<String>("route")?.forEach { routingDescriptor ->
			val (host, targetPort) = routingDescriptor.split(',')
			this[host] = targetPort.toInt()
		}
	}

	val redirectionTable = buildMap {
		arguments.gets<String>("redirect")?.forEach { redirectionDescriptor ->
			val (host, targetURI, permanent) = redirectionDescriptor.split(',')
			this[host] = targetURI to permanent.toBooleanStrict()
		}
	}

	fun operation(
		net: InetAddress, family: ProtocolFamily, port: Int,
		operation: (
			ServerSocketChannel,
			Map<String, Int>,
			Map<String, Pair<String, Boolean>>,
			ArgumentContainer
		) -> Unit
	) {
		val socket = ServerSocketChannel.open(family)
		socket.bind(InetSocketAddress(net, port))
		Thread.ofPlatform().start {
			operation(socket, routingTable, redirectionTable, arguments)
		}
	}

	val (insecure, secure) = arguments.getRequired(ipFlag)
	val (insecurePort, securePort) = arguments.getRequired(portFlag)
	insecure?.let { insecureIP ->
		if (insecurePort == null)
			throw IllegalArgumentException("Insecure port must be set if insecure IP [$insecureIP] is set")
		logger.info("[$insecureIP : $insecurePort] Insecure operation")
		operation(insecureIP, StandardProtocolFamily.INET6, insecurePort, ::insecureOperation)
	}
	secure?.let { secureIP ->
		if (securePort == null)
			throw IllegalArgumentException("Secure port must be set if secure IP [$secureIP] is set")
		logger.info("[$secureIP : $securePort] Secure operation")
		operation(secureIP, StandardProtocolFamily.INET6, securePort, ::secureOperation)
	}
}