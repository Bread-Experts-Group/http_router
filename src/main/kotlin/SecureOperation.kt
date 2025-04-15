package bread_experts_group

import bread_experts_group.http.HTTPRequest
import bread_experts_group.http.HTTPResponse
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.logging.Logger
import javax.net.ssl.SSLException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

private val secureLogger = Logger.getLogger("HTTP Routing, Secure")

fun secureOperation(
	secureServerSocket: SSLServerSocket,
	routingTable: Map<String, Int>,
	redirectionTable: Map<String, Pair<String, Boolean>>
) = Runnable {
	while (true) {
		secureLogger.finer("Waiting for next socket")
		val sock = secureServerSocket.accept() as SSLSocket
		val localLogger = Logger.getLogger("${secureLogger.name}.${sock.remoteSocketAddress}")
		localLogger.finer("Setting SSL parameters")
		val parameters = sock.sslParameters
		parameters.wantClientAuth = false
		parameters.applicationProtocols = arrayOf("http/1.1")
		sock.sslParameters = parameters
		localLogger.finer("Starting SSL handshake")
		sock.startHandshake()
		localLogger.fine("Thread start")
		Thread.ofVirtual().name("Routing-${sock.remoteSocketAddress}").start {
			try {
				localLogger.fine {
					buildString {
						val s = sock.session
						appendLine("${s.protocol} ${s.cipherSuite} \"${s.peerHost}:${s.peerPort}\"")
						appendLine("Peer Principal: ${s.peerPrincipal.name}")
						appendLine("Peer Certificates:")
						s.peerCertificates.forEachIndexed { index, c ->
							appendLine(" $index: ${c.type}, pub key: (${c.publicKey.format}, ${c.publicKey.algorithm})")
						}
					}
				}
				val request = HTTPRequest.read(sock.inputStream)
				val host = request.headers["Host"]
				if (host == null) {
					localLogger.warning("No host?")
					HTTPResponse(400, request.version, emptyMap(), "")
						.write(sock.outputStream)
					return@start
				}
				val redirection = redirectionTable[host]
				if (redirection != null) {
					val (uri, permanent) = redirection
					localLogger.info { "Redirecting (${if (permanent) "permanent" else "temporary"}), $host -> $uri" }
					HTTPResponse(
						if (permanent) 308 else 307, request.version,
						mapOf("Location" to uri), ""
					).write(sock.outputStream)
					return@start
				}
				val route = routingTable[host]
				if (route != null) {
					localLogger.info { "Routing, $host${request.path} -> $route" }
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
						localLogger.severe { "Host \"$host\" not responding for request: $request" }
						HTTPResponse(503, request.version, emptyMap(), "")
							.write(sock.outputStream)
						sock.close()
						pipeSocket.close()
					} catch (_: ConnectException) {
						localLogger.severe { "Host \"$host\" refused for request: $request" }
						HTTPResponse(500, request.version, emptyMap(), "")
							.write(sock.outputStream)
						sock.close()
						pipeSocket.close()
					}
				} else {
					localLogger.warning { "No route for host \"$host\", request: $request" }
					HTTPResponse(404, request.version, emptyMap(), "")
						.write(sock.outputStream)
				}
			} catch (e: SSLException) {
				localLogger.warning { "SSL failure encountered; ${e.localizedMessage}" }
				sock.close()
			} catch (e: IOException) {
				localLogger.warning { "IO failure encountered; ${e.localizedMessage}" }
				sock.close()
			}
		}
	}
}