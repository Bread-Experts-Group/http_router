package org.bread_experts_group.http_router

import org.bread_experts_group.command_line.ArgumentContainer
import org.bread_experts_group.command_line.Flag
import org.bread_experts_group.command_line.readArgs
import org.bread_experts_group.command_line.stringToInt
import org.bread_experts_group.logging.ColoredHandler
import java.io.File
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ProtocolFamily
import java.net.StandardProtocolFamily
import java.nio.channels.ServerSocketChannel

// TODO: Save to file / log
val connectionStats = mutableMapOf<String, ConnectionStats>()

val ipFlag = Flag(
	"ips",
	"The IP addresses on which to listen to.\nFormat: addr4http,addr4https]addr6http,addr4https",
	default = run {
		val all = InetAddress.getAllByName(InetAddress.getLocalHost().hostName)
		val v4 = all.firstNotNullOfOrNull { it as? Inet4Address }
		val v6 = all.firstNotNullOfOrNull { it as? Inet6Address }
		(v4 to v4) to (v6 to v6)
	},
	conv = {
		val (v4, v6) = it.split(']')
			.also { sets ->
				if (sets.size != 2) throw IllegalArgumentException("There must be two sets of addresses.")
			}.let { sets ->
				val v4 = sets[0]
					.split(',')
					.map { addr -> if (addr.isEmpty()) null else InetAddress.getByName(addr) as Inet4Address }
				val v6 = (sets.getOrNull(1) ?: "")
					.split(',')
					.map { addr -> if (addr.isEmpty()) null else InetAddress.getByName(addr) as Inet6Address }
				v4 to v6
			}
		val v4Selected = v4.getOrNull(0) to v4.getOrNull(1)
		val v6Selected = v6.getOrNull(0) to v6.getOrNull(1)
		v4Selected to v6Selected
	}
)
val portFlag = Flag(
	"ports", "The TCP ports on which to listen to.\nFormat: port4http,port4https]port6http,port6https",
	default = (80 to 443) to (80 to 443),
	conv = {
		val selector = stringToInt(0..65535)
		val (v4p, v6p) = it.split(']')
			.also { sets ->
				if (sets.size != 2) throw IllegalArgumentException("There must be two sets of ports.")
			}.let { sets ->
				val v4 = sets[0]
					.split(',')
					.map { port -> if (port.isEmpty()) null else selector.invoke(port) }
				val v6 = (sets.getOrNull(1) ?: "")
					.split(',')
					.map { port -> if (port.isEmpty()) null else selector.invoke(port) }
				v4 to v6
			}
		val v4pSelected = v4p.getOrNull(0) to v4p.getOrNull(1)
		val v6pSelected = v6p.getOrNull(0) to v6p.getOrNull(1)
		v4pSelected to v6pSelected
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
		arguments.getsRequired<String>("route").forEach { routingDescriptor ->
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

	val (v4, v6) = arguments.getRequired(ipFlag)
	val (v4p, v6p) = arguments.getRequired(portFlag)
	v4.first?.let { ipv4 ->
		val v4pi = v4p.first
		if (v4pi == null)
			throw IllegalArgumentException("v4 port, insecure, must be set if v4 IP [$ipv4], insecure, is set")
		logger.info("[$ipv4 : $v4pi] Insecure operation")
		operation(ipv4, StandardProtocolFamily.INET, v4pi, ::insecureOperation)
	}
	v4.second?.let { ipv4 ->
		val v4ps = v4p.second
		if (v4ps == null)
			throw IllegalArgumentException("v4 port, secure, must be set if v4 IP [$ipv4], secure, is set")
		logger.info("[$ipv4 : $v4ps] Secure operation")
		operation(ipv4, StandardProtocolFamily.INET, v4ps, ::secureOperation)
	}
	v6.first?.let { ipv6 ->
		val v6pi = v6p.first
		if (v6pi == null)
			throw IllegalArgumentException("v6 port, insecure, must be set if v6 IP [$ipv6], insecure, is set")
		logger.info("[$ipv6 : $v6pi] Insecure operation")
		operation(ipv6, StandardProtocolFamily.INET6, v6pi, ::insecureOperation)
	}
	v6.second?.let { ipv6 ->
		val v6ps = v6p.second
		if (v6ps == null)
			throw IllegalArgumentException("v6 port, secure, must be set if v6 IP [$ipv6], secure, is set")
		logger.info("[$ipv6 : $v6ps] Secure operation")
		operation(ipv6, StandardProtocolFamily.INET6, v6ps, ::secureOperation)
	}
}