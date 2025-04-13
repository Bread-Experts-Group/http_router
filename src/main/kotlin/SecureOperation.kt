package bread_experts_group

import bread_experts_group.http.HTTPRequest
import bread_experts_group.http.HTTPResponse
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import javax.net.ssl.SSLException
import javax.net.ssl.SSLServerSocket

fun secureOperation(
	secureServerSocket: SSLServerSocket,
	routingTable: Map<String, Int>,
	redirectionTable: Map<String, Pair<String, Boolean>>
) = Runnable {
	while (true) {
		val sock = secureServerSocket.accept()
		Thread.ofVirtual().name("Routing-${sock.localSocketAddress}<${sock.remoteSocketAddress}").start {
			try {
				val request = HTTPRequest.read(sock.inputStream)
				val host = request.headers["Host"]
				if (host == null) {
					info("No host?")
					HTTPResponse(400, request.version, emptyMap(), "")
						.write(sock.outputStream)
					return@start
				}
				val redirection = redirectionTable[host]
				if (redirection != null) {
					val (uri, permanent) = redirection
					info("Redirecting (${if (permanent) "permanent" else "temporary"}), $host -> $uri${request.path}")
					HTTPResponse(
						if (permanent) 308 else 307, request.version,
						mapOf("Location" to uri), ""
					).write(sock.outputStream)
					return@start
				}
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
						HTTPResponse(503, request.version, emptyMap(), "")
							.write(sock.outputStream)
						sock.close()
						pipeSocket.close()
					} catch (_: ConnectException) {
						error("Host \"$host\" refused for request: $request")
						HTTPResponse(500, request.version, emptyMap(), "")
							.write(sock.outputStream)
						sock.close()
						pipeSocket.close()
					}
				} else {
					warn("No route for host \"$host\", request: $request")
					HTTPResponse(404, request.version, emptyMap(), "")
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