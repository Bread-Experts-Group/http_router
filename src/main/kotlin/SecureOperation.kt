package org.bread_experts_group.http_router

import org.bread_experts_group.http.HTTPRequest
import org.bread_experts_group.http.HTTPResponse
import org.bread_experts_group.http.HTTPVersion
import org.bread_experts_group.logging.ColoredLogger
import org.bread_experts_group.truncateSI
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URISyntaxException
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLHandshakeException
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
		val localLogger = ColoredLogger.newLogger("${secureLogger.name}.${sock.remoteSocketAddress}")
		sock.keepAlive = true
		sock.setSoLinger(true, 2)
		Thread.ofVirtual().name("Routing-${sock.remoteSocketAddress}").start {
			var rx = 0L
			var tx = 0L
			try {
				sock.startHandshake()
				val s = sock.session as ExtendedSSLSession
				val reqNames = s.requestedServerNames.mapNotNull { (it as? SNIHostName)?.asciiName }
				localLogger.info {
					buildString {
						appendLine("Handshake Complete: ${s.protocol} ${s.cipherSuite} \"${s.peerHost}:${s.peerPort}\"")
						append("[${sock.applicationProtocol.ifEmpty { "No ALPN" }}] ")
						appendLine(reqNames)
						val (principal, certs) = try {
							s.peerPrincipal to s.peerCertificates
						} catch (_: SSLPeerUnverifiedException) {
							null to null
						}
						if (principal != null && certs != null) {
							appendLine("Peer Principal: ${principal.name}")
							append("Peer Certificates:")
							certs.forEachIndexed { index, c -> append("\n $index: ${c.type}, ${c.publicKey}") }
						} else {
							append("No peer authenticity")
						}
					}
				}
				var consumedRequest: HTTPRequest? = null
				val host = if (reqNames.isNotEmpty()) {
					val sniHost = reqNames.firstOrNull { (redirectionTable[it] != null) || (routingTable[it] != null) }
					if (sniHost == null) throw SocketException()
					sniHost
				} else {
					val request = try {
						HTTPRequest.read(sock.inputStream)
					} catch (_: URISyntaxException) {
						HTTPResponse(400, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
							.write(sock.outputStream)
						throw SocketException()
					}
					consumedRequest = request
					val readHost = request.headers["Host"]
					if (readHost == null) {
						if (reqNames.isEmpty())
							HTTPResponse(400, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
								.write(sock.outputStream)
						throw SocketException()
					}
					readHost
				}
				val redirection = redirectionTable[host]
				if (redirection != null) {
					val (uri, permanent) = redirection
					localLogger.info { "Redirecting (${if (permanent) "permanent" else "temporary"}), $host -> $uri" }
					HTTPResponse(
						if (permanent) 308 else 307, HTTPVersion.HTTP_1_1,
						mapOf(
							"Location" to uri,
							"Connection" to "close"
						)
					).write(sock.outputStream)
					throw SocketException()
				}
				val route = routingTable[host]
				if (route != null) {
					localLogger.info { "Routing, $host -> $route" }
					val pipeSocket = Socket()
					try {
						pipeSocket.connect(InetSocketAddress("localhost", route), 4000)
						val remoteToLocal = Thread.ofVirtual().start {
							try {
								val buffer = ByteArray(16384)
								while (true) {
									val read = sock.inputStream.read(buffer)
									if (read == -1) break
									pipeSocket.outputStream.write(buffer, 0, read)
									rx += read
								}
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
								val buffer = ByteArray(16384)
								while (true) {
									val read = pipeSocket.inputStream.read(buffer)
									if (read == -1) break
									sock.outputStream.write(buffer, 0, read)
									tx += read
								}
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
						consumedRequest?.write(pipeSocket.outputStream)
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
					localLogger.warning { "No route for host \"$host\"" }
					HTTPResponse(404, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
						.write(sock.outputStream)
				}
			} catch (_: SocketTimeoutException) {
			} catch (_: SocketException) {
			} catch (_: SSLHandshakeException) {
			} catch (e: IOException) {
				localLogger.warning { "IO failure encountered; [${e.javaClass.canonicalName}] ${e.localizedMessage}" }
			} finally {
				sock.close()
			}
			localLogger.info {
				"Connection finished; sent ${truncateSI(tx, 2)}B, received ${truncateSI(rx, 2)}B"
			}
		}
	}
}