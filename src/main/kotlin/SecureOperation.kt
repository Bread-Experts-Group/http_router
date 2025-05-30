package org.bread_experts_group.http_router

import org.bread_experts_group.http.HTTPRequest
import org.bread_experts_group.http.HTTPResponse
import org.bread_experts_group.http.HTTPVersion
import org.bread_experts_group.logging.ColoredLogger
import org.bread_experts_group.truncateSI
import java.io.IOException
import java.io.InputStream
import java.net.*
import java.util.concurrent.CountDownLatch
import javax.net.ssl.*


fun secureOperation(
	secureServerSocket: SSLServerSocket,
	routingTable: Map<String, Int>,
	redirectionTable: Map<String, Pair<String, Boolean>>
) = Runnable {
	while (true) {
		val socket = secureServerSocket.accept() as SSLSocket
		socket.keepAlive = true
		val remoteSockAddr = socket.remoteSocketAddress.toString()
		val localLogger = ColoredLogger.newLogger("HTTPS $remoteSockAddr")
		Thread.ofVirtual().name("Routing $remoteSockAddr").start {
			val pipeSocket = Socket()
			val hostStr = (socket.remoteSocketAddress as InetSocketAddress).hostString
			val stats = connectionStats.getOrPut(hostStr) { ConnectionStats(0, 0, 0) }
			stats.connections++
			try {
				val s = socket.session as ExtendedSSLSession
				val reqNames = s.requestedServerNames.mapNotNull { (it as? SNIHostName)?.asciiName }
				localLogger.info {
					buildString {
						appendLine("Handshake Complete: ${s.protocol} ${s.cipherSuite}")
						append("[${socket.applicationProtocol.ifEmpty { "No ALPN" }}] ")
						append(reqNames)
						val (principal, certs) = try {
							s.peerPrincipal to s.peerCertificates
						} catch (_: SSLPeerUnverifiedException) {
							null to null
						}
						if (principal != null && certs != null) {
							appendLine("\nPeer Principal: ${principal.name}")
							append("Peer Certificates:")
							certs.forEachIndexed { index, c -> append("\n $index: ${c.type}, ${c.publicKey}") }
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
						HTTPRequest.read(socket.inputStream)
					} catch (_: URISyntaxException) {
						HTTPResponse(400, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
							.write(socket.outputStream)
						throw SocketException()
					}
					consumedRequest = request
					val readHost = request.headers["Host"]
					if (readHost == null) {
						if (reqNames.isEmpty())
							HTTPResponse(400, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
								.write(socket.outputStream)
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
					).write(socket.outputStream)
					throw SocketException()
				}
				val route = routingTable[host]
				if (route != null) {
					localLogger.info { "Routing, $host -> $route" }
					try {
						pipeSocket.connect(InetSocketAddress("localhost", route))
						val countDown = CountDownLatch(2)
						Thread.ofVirtual().start {
							try {
								val buffer = ByteArray(socket.receiveBufferSize)
								var read: Int
								while (socket.inputStream.read(buffer).also { read = it } != -1) {
									stats.rx += read
									pipeSocket.outputStream.write(buffer, 0, read)
								}
							} catch (e: IOException) {
								localLogger.warning {
									"RTL exception: [${e.javaClass.canonicalName}]: ${e.localizedMessage}"
								}
							} finally {
								countDown.countDown()
							}
						}
						Thread.ofVirtual().start {
							try {
								val buffer = ByteArray(socket.sendBufferSize)
								var read: Int
								while (pipeSocket.inputStream.read(buffer).also { read = it } != -1) {
									socket.outputStream.write(buffer, 0, read)
									stats.tx += read
								}
							} catch (e: IOException) {
								localLogger.warning {
									"LTR exception: [${e.javaClass.canonicalName}]: ${e.localizedMessage}"
								}
							} finally {
								countDown.countDown()
							}
						}
						consumedRequest?.write(pipeSocket.outputStream)
						countDown.await()
						socket.shutdownOutput()
						socket.shutdownInput()
					} catch (e: IOException) {
						localLogger.severe {
							"Host \"$host\" refused! [${e.javaClass.canonicalName}: ${e.localizedMessage}]"
						}
						HTTPResponse(503, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
							.write(socket.outputStream)
					} finally {
						socket.close()
						pipeSocket.close()
					}
				} else {
					localLogger.warning { "No route for host \"$host\"" }
					HTTPResponse(404, HTTPVersion.HTTP_1_1, mapOf("Connection" to "close"))
						.write(socket.outputStream)
				}
			} catch (_: SocketTimeoutException) {
			} catch (_: SSLHandshakeException) {
			} catch (_: SocketException) {
			} catch (e: IOException) {
				localLogger.warning { "IO failure encountered; [${e.javaClass.canonicalName}] ${e.localizedMessage}" }
			} finally {
				socket.close()
				pipeSocket.close()
				localLogger.info {
					"Connection finished; sent ${truncateSI(stats.tx)}B, received ${truncateSI(stats.rx)}B"
				}
			}
		}
	}
}