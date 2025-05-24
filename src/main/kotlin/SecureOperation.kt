package org.bread_experts_group.router

import org.bread_experts_group.http.HTTPRequest
import org.bread_experts_group.http.HTTPResponse
import org.bread_experts_group.http.HTTPVersion
import org.bread_experts_group.logging.ColoredLogger
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URISyntaxException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.collections.forEachIndexed

private val secureLogger = ColoredLogger.newLogger("HTTP Routing, Secure")

fun secureOperation(
	secureServerSocket: SSLServerSocket,
	routingTable: Map<String, Int>,
	redirectionTable: Map<String, Pair<String, Boolean>>
) = Runnable {
	while (true) {
		secureLogger.finer("Waiting for next socket")
		val sock = secureServerSocket.accept() as SSLSocket
		sock.keepAlive = true
		sock.soTimeout = 25000
		sock.setSoLinger(true, 2)
		Thread.ofVirtual().name("Routing-${sock.remoteSocketAddress}").start {
			val localLogger = ColoredLogger.newLogger("${secureLogger.name}.${sock.remoteSocketAddress}")
			try {
				localLogger.fine("Thread start")
				localLogger.info {
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
					throw IOException()
				}
				val host = request.headers["Host"]
				if (host == null) {
					HTTPResponse(400, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
						.write(sock.outputStream)
					throw IOException()
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
					throw IOException()
				}
				val route = routingTable[host]
				if (route != null) {
					localLogger.info { "Routing, $host${request.path} -> $route" }
					val pipeSocket = Socket()
					try {
						pipeSocket.connect(InetSocketAddress("localhost", route), 4000)
						val remoteToLocal = Thread.ofVirtual().start {
							try {
								sock.inputStream.transferTo(pipeSocket.outputStream)
							} catch (_: SocketTimeoutException) {
							} catch (_: SocketException) {
							} catch (e: IOException) {
								localLogger.warning {
									"RTL exception: [${e.javaClass.canonicalName}]: ${e.localizedMessage}"
								}
							} finally {
								sock.close()
								pipeSocket.close()
							}
						}
						val localToRemote = Thread.ofVirtual().start {
							try {
								pipeSocket.inputStream.transferTo(sock.outputStream)
							} catch (_: SocketTimeoutException) {
							} catch (_: SocketException) {
							} catch (e: IOException) {
								localLogger.warning {
									"LTR exception: [${e.javaClass.canonicalName}]: ${e.localizedMessage}"
								}
							} finally {
								sock.close()
								pipeSocket.close()
							}
						}
						request.write(pipeSocket.outputStream)
						remoteToLocal.join()
						localToRemote.join()
					} catch (e: IOException) {
						localLogger.severe {
							"Host \"$host\" refused! [${e.javaClass.canonicalName}: ${e.localizedMessage}]"
						}
						HTTPResponse(503, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
							.write(sock.outputStream)
					} finally {
						sock.close()
						pipeSocket.close()
					}
				} else {
					localLogger.warning { "No route for host \"$host\", request: $request" }
					HTTPResponse(404, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
						.write(sock.outputStream)
				}
			} catch (_: SocketTimeoutException) {
			} catch (_: SocketException) {
			} catch (e: IOException) {
				localLogger.warning { "IO failure encountered; [${e.javaClass.canonicalName}] ${e.localizedMessage}" }
			} finally {
				sock.close()
			}
		}
	}
}