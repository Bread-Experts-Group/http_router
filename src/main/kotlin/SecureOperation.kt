package org.bread_experts_group

import org.bread_experts_group.http.HTTPRequest
import org.bread_experts_group.http.HTTPResponse
import org.bread_experts_group.http.HTTPVersion
import java.io.EOFException
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URISyntaxException
import java.util.logging.Logger
import javax.net.ssl.SSLException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.collections.forEachIndexed

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
		localLogger.fine("Thread start")
		Thread.ofVirtual().name("Routing-${sock.remoteSocketAddress}").start {
			try {
				localLogger.fine {
					buildString {
						val s = sock.session
						appendLine("${s.protocol} ${s.cipherSuite} \"${s.peerHost}:${s.peerPort}\"")
						val (principal, certs) = try {
							s.peerPrincipal to s.peerCertificates
						} catch (_: SSLPeerUnverifiedException) {
							null to null
						}
						if (principal != null && certs != null) {
							appendLine("Peer Principal: ${principal.name}")
							appendLine("Peer Certificates:")
							certs.forEachIndexed { index, c ->
								appendLine(" $index: ${c.type}, pubkey: (${c.publicKey.format}, ${c.publicKey.algorithm})")
							}
						} else {
							appendLine("No peer authenticity")
						}
					}
				}
				val request = try {
					HTTPRequest.read(sock.inputStream)
				} catch (_: URISyntaxException) {
					HTTPResponse(400, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
						.write(sock.outputStream)
					throw EOFException()
				}
				val host = request.headers["Host"]
				if (host == null) {
					HTTPResponse(400, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
						.write(sock.outputStream)
					throw EOFException()
				}
				val redirection = redirectionTable[host]
				if (redirection != null) {
					val (uri, permanent) = redirection
					localLogger.info { "Redirecting (${if (permanent) "permanent" else "temporary"}), $host -> $uri" }
					HTTPResponse(
						if (permanent) 308 else 307, request.version,
						mapOf(
							"Location" to uri,
							"Connection" to "close"
						)
					).write(sock.outputStream)
					throw EOFException()
				}
				val route = routingTable[host]
				if (route != null) {
					localLogger.info { "Routing, $host${request.path} -> $route" }
					val pipeSocket = Socket()
					try {
						pipeSocket.connect(InetSocketAddress("localhost", route), 4000)
						val a = Thread.ofVirtual().start {
							pipeSocket.inputStream.transferTo(sock.outputStream)
						}
						val b = Thread.ofVirtual().start {
							sock.inputStream.transferTo(pipeSocket.outputStream)
						}
						request.write(pipeSocket.outputStream)
						a.join()
						b.join()
					} catch (_: SocketTimeoutException) {
						localLogger.severe { "Host \"$host\" not responding for request: $request" }
						HTTPResponse(503, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
							.write(sock.outputStream)
					} catch (_: ConnectException) {
						localLogger.severe { "Host \"$host\" refused for request: $request" }
						HTTPResponse(500, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
							.write(sock.outputStream)
					}
					pipeSocket.close()
				} else {
					localLogger.warning { "No route for host \"$host\", request: $request" }
					HTTPResponse(404, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
						.write(sock.outputStream)
				}
			} catch (_: EOFException) {
			} catch (e: SSLException) {
				localLogger.warning { "SSL failure encountered; ${e.localizedMessage}" }
			} catch (e: IOException) {
				localLogger.warning { "IO failure encountered; ${e.localizedMessage}" }
			}
			sock.close()
		}
	}
}