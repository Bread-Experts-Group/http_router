package bread_experts_group

import bread_experts_group.http.HTTPRequest
import bread_experts_group.http.HTTPResponse
import java.io.File
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import javax.net.ssl.SSLException

fun main(args: Array<String>) {
	Thread.currentThread().name = "Routing-Main"
	debug("- Argument read")
	val (singleArgs, multipleArgs) = readArgs(
		args,
		Flag<String>("keystore"),
		Flag<String>("keystore_passphrase"),
		Flag<String>("ip"),
		Flag<Int>("port", default = 443, conv = ::stringToInt),
		Flag<Int>("verbosity", default = 1, conv = ::stringToInt),
		Flag<String>("route", repeatable = true)
	)
	toStringVerbosity = (singleArgs["verbosity"] as? Int) ?: toStringVerbosity
	debug("- Socket retrieval")
	val tlsSocket = getTLSContext(
		File(singleArgs.getValue("keystore") as String),
		singleArgs.getValue("keystore_passphrase") as String,
	)
	val serverSocket = tlsSocket.getServerSocket()
	debug("- Socket bind")
	serverSocket.bind(
		InetSocketAddress(
			(singleArgs["ip"] as? String) ?: "0.0.0.0",
			singleArgs["port"] as Int
		),
	)
	info("- Server loop")
	val routingTable = buildMap {
		multipleArgs.getValue("route").forEach { routingDescriptor ->
			val (host, targetPort) = (routingDescriptor as String).split(',')
			this[host] = targetPort.toInt()
		}
	}
	while (true) {
		val sock = serverSocket.accept()
		Thread.ofVirtual().name("Routing-${sock.localPort}<${sock.inetAddress}").start {
			try {
				val request = HTTPRequest.read(sock.inputStream)
				val host = request.headers["Host"] ?: "localhost"
				val route = routingTable[host]
				if (route != null) {
					info("Routing, $host${request.path} -> $route")
					val pipeSocket = Socket()
					try {
						pipeSocket.connect(InetSocketAddress("localhost", route), 4000)
						request.write(pipeSocket.outputStream)
						Thread.ofVirtual().start {
							try {
								sock.inputStream.transferTo(pipeSocket.outputStream)
							} catch (_: Exception) {
								sock.close()
								pipeSocket.close()
							}
						}
						Thread.ofVirtual().start {
							try {
								pipeSocket.inputStream.transferTo(sock.outputStream)
							} catch (_: Exception) {
								sock.close()
								pipeSocket.close()
							}
						}
					} catch (_: SocketTimeoutException) {
						error("Host \"$host\" not responding for request: $request")
						HTTPResponse(503, request.version)
							.write(sock.outputStream)
						sock.close()
						pipeSocket.close()
					} catch (_: ConnectException) {
						error("Host \"$host\" refused for request: $request")
						HTTPResponse(500, request.version)
							.write(sock.outputStream)
						sock.close()
						pipeSocket.close()
					}
				} else {
					warn("No route for host \"$host\", request: $request")
					HTTPResponse(404, request.version)
						.write(sock.outputStream)
				}
			} catch (e: SSLException) {
				warn("SSL failure encountered; ${e.localizedMessage}")
				sock.close()
			} catch (e: IOException) {
				warn("IO failure encountered; ${e.localizedMessage}")
				sock.close()
			}
		}
	}
}