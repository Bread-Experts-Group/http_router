package org.bread_experts_group.http_router

import org.bread_experts_group.StandardUncaughtExceptionHandler
import org.bread_experts_group.command_line.ArgumentContainer
import org.bread_experts_group.getTLSContext
import org.bread_experts_group.goodSchemes
import org.bread_experts_group.http.HTTPProtocolSelector
import org.bread_experts_group.http.HTTPRequest
import org.bread_experts_group.http.HTTPResponse
import org.bread_experts_group.http.HTTPVersion
import org.bread_experts_group.logging.ColoredHandler
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.net.StandardSocketOptions
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicLong
import java.util.function.BiFunction
import java.util.logging.Level
import javax.net.ssl.*
import kotlin.math.min

fun secureOperation(
	secureServerSocket: ServerSocketChannel,
	routingTable: Map<String, Int>,
	redirectionTable: Map<String, Pair<String, Boolean>>,
	arguments: ArgumentContainer
) {
	val tlsContext = getTLSContext(
		arguments.getRequired("keystore"),
		arguments.getRequired("keystore_passphrase"),
	)

	while (true) {
		val sock = secureServerSocket.accept()
		sock.setOption(StandardSocketOptions.SO_KEEPALIVE, true)
		val remoteAddress = sock.remoteAddress as InetSocketAddress
		val stats = connectionStats.getOrPut(remoteAddress.hostString) {
			ConnectionStats(AtomicLong(), AtomicLong(), 0)
		}
		stats.connections++
		val localLogger = ColoredHandler.newLogger("HTTPS.$remoteAddress")
		Thread.ofVirtual().name("HTTPS.$remoteAddress").start {
			val engine = tlsContext.createSSLEngine(remoteAddress.hostString, remoteAddress.port)
			val parameters = engine.sslParameters
			parameters.useCipherSuitesOrder = true
			parameters.cipherSuites = goodSchemes
			parameters.protocols = arrayOf("TLSv1.2", "TLSv1.3")
			engine.sslParameters = parameters
			engine.useClientMode = false
			engine.wantClientAuth = true
			engine.handshakeApplicationProtocolSelector = BiFunction { engine: SSLEngine, protocols: List<String> ->
//				if (protocols.contains("h2")) return@BiFunction "h2"
				if (protocols.contains("http/1.1")) return@BiFunction "http/1.1"
				if (protocols.contains("http/1.0")) return@BiFunction "http/1.0"
				if (protocols.contains("http/0.9")) return@BiFunction "http/0.9"
				null
			}
			engine.beginHandshake()
			val tlsIn = ByteBuffer.allocate(engine.session.packetBufferSize)
			var tlsOut = ByteBuffer.allocate(engine.session.packetBufferSize)
			var dataIn = ByteBuffer.allocate(engine.session.applicationBufferSize)
			val dataOut = ByteBuffer.allocate(engine.session.applicationBufferSize)
			val pipeSocket = Socket()
			fun shutdown() {
				if (sock.isOpen) {
					sock.shutdownInput()
					sock.shutdownOutput()
				}
				sock.close()
				pipeSocket.close()
				localLogger.info("Goodbye")
			}
			tlsIn.limit(0)
			tlsOut.limit(0)
			try {
				var handshakeStatus = engine.handshakeStatus
				while (
					handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED &&
					handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
				) when (handshakeStatus) {
					SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
						val result = engine.unwrap(tlsIn, dataIn)
						handshakeStatus = result.handshakeStatus
						when (result.status) {
							SSLEngineResult.Status.OK -> {}
							SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
								tlsIn.compact()
								val read = sock.read(tlsIn).toLong()
								if (read == -1L) throw IOException("Socket closed")
								stats.rx.addAndGet(read)
								tlsIn.flip()
							}

							SSLEngineResult.Status.CLOSED -> {
								shutdown()
								return@start
							}

							else -> throw IllegalStateException("Unexpected SSLEngineResult: $result")
						}
					}

					SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
						val result = engine.wrap(dataOut, tlsOut)
						handshakeStatus = result.handshakeStatus
						when (result.status) {
							SSLEngineResult.Status.OK -> {
								tlsOut.flip()
								stats.tx.addAndGet(sock.write(tlsOut).toLong())
								tlsOut.clear()
							}

							SSLEngineResult.Status.BUFFER_OVERFLOW -> {
								val newBuffer = ByteBuffer.allocate(engine.session.packetBufferSize)
								newBuffer.put(tlsOut)
								tlsOut = newBuffer
							}

							SSLEngineResult.Status.CLOSED -> {
								shutdown()
								return@start
							}

							else -> throw IllegalStateException("Unexpected SSLEngineResult: $result")
						}
					}

					SSLEngineResult.HandshakeStatus.NEED_TASK -> {
						do {
							val nextTask = engine.delegatedTask
							nextTask?.run()
						} while (nextTask != null)
						handshakeStatus = engine.handshakeStatus
					}

					else -> TODO(engine.handshakeStatus.name)
				}
			} catch (_: IOException) {
				shutdown()
				return@start
			} catch (e: Exception) {
				localLogger.log(Level.WARNING, e) { "Problem during SSL handshake" }
				shutdown()
				return@start
			}
			try {
				val s = engine.session as ExtendedSSLSession
				val reqNames = s.requestedServerNames.mapNotNull { (it as? SNIHostName)?.asciiName }
				localLogger.info {
					buildString {
						appendLine("Handshake Complete: ${s.protocol} ${s.cipherSuite}")
						append("[${(engine.applicationProtocol ?: "").ifEmpty { "No ALPN" }}] ")
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
				dataIn.limit(0)
				val selector = HTTPProtocolSelector(
					when (engine.applicationProtocol) {
						"h2" -> HTTPVersion.HTTP_2
						"http/1.0" -> HTTPVersion.HTTP_1_0
						"http/0.9" -> HTTPVersion.HTTP_0_9
						else -> HTTPVersion.HTTP_1_1
					},
					object : InputStream() {
						private fun prepData() {
							val result = engine.unwrap(tlsIn, dataIn)
							when (result.status) {
								SSLEngineResult.Status.OK -> {
									dataIn.flip()
									return
								}

								SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
									tlsIn.compact()
									val read = sock.read(tlsIn).toLong()
									if (read == -1L) throw IOException("Socket closed")
									stats.rx.addAndGet(read)
									tlsIn.flip()
								}

								SSLEngineResult.Status.BUFFER_OVERFLOW -> {
									val newBuffer = ByteBuffer.allocate(engine.session.applicationBufferSize)
									newBuffer.put(dataIn)
									dataIn = newBuffer
								}

								SSLEngineResult.Status.CLOSED -> throw IOException("SSLEngine closed")
								else -> throw IllegalStateException("Unexpected SSLEngineResult: $result")
							}
							return prepData()
						}

						override fun read(): Int {
							if (dataIn.hasRemaining()) return dataIn.get().toInt() and 0xFF
							else {
								prepData()
								return dataIn.get().toInt() and 0xFF
							}
						}
					},
					object : OutputStream() {
						override fun write(b: Int) {
							write(byteArrayOf(b.toByte()), 0, 1)
						}

						override fun write(b: ByteArray, off: Int, len: Int) {
							var position = 0
							while (position < len) {
								dataOut.clear()
								val length = min(len - position, dataOut.remaining())
								dataOut.put(b, off + position, length)
								position += length
								dataOut.flip()

								while (dataOut.hasRemaining()) {
									tlsOut.clear()
									val result = engine.wrap(dataOut, tlsOut)
									when (result.status) {
										SSLEngineResult.Status.OK -> {
											tlsOut.flip()
											while (tlsOut.hasRemaining()) {
												val written = sock.write(tlsOut).toLong()
												if (written == -1L) throw IOException("Socket closed")
												stats.tx.addAndGet(written)
											}
										}

										SSLEngineResult.Status.CLOSED -> throw IOException("SSLEngine closed")
										else -> throw IllegalStateException("Unexpected SSLEngineResult: $result")
									}
								}
							}
						}
					},
					true
				)
				val request: HTTPRequest = selector.nextRequest().getOrThrow()
				val host = if (reqNames.isNotEmpty()) reqNames.firstOrNull {
					(redirectionTable[it] != null) || (routingTable[it] != null)
				} else request.headers["Host"]
				if (host == null) {
					selector.sendResponse(HTTPResponse(request, 400))
					shutdown()
					return@start
				}
				val redirection = redirectionTable[host]
				if (redirection != null) {
					val (uri, permanent) = redirection
					localLogger.info { "Redirecting (${if (permanent) "permanent" else "temporary"}), $host -> $uri" }
					selector.sendResponse(
						HTTPResponse(
							request,
							if (permanent) 308 else 307,
							mapOf(
								"Location" to uri,
								"Connection" to "close"
							)
						)
					)
					throw SocketException()
				}
				val route = routingTable[host]
				if (route != null) {
					localLogger.info { "Routing, $host -> $route" }
					try {
						pipeSocket.connect(InetSocketAddress("localhost", route))
						val downgradeOutput = ByteArrayOutputStream()
						val downgradeSelector = HTTPProtocolSelector(
							HTTPVersion.HTTP_1_1,
							null,
							downgradeOutput,
							false
						)
						val countDown = CountDownLatch(2)

						lateinit var rtl: Thread
						val ltr: Thread = Thread.ofVirtual().name("${Thread.currentThread().name}.LTR").start {
							try {
								val ltrSelector = HTTPProtocolSelector(
									HTTPVersion.HTTP_1_1,
									pipeSocket.inputStream, OutputStream.nullOutputStream(),
									false
								)
								while (!Thread.currentThread().isInterrupted)
									selector.sendResponse(ltrSelector.nextResponse().getOrThrow())
							} catch (_: IOException) {
							} catch (_: InterruptedException) {
							} catch (e: Exception) {
								localLogger.log(Level.WARNING, e) { "LTR operation problem" }
							} finally {
								countDown.countDown()
								rtl.interrupt()
							}
						}

						rtl = Thread.ofVirtual().name("${Thread.currentThread().name}.RTL").start {
							try {
								val rtlSelector = HTTPProtocolSelector(
									HTTPVersion.HTTP_1_1,
									null, pipeSocket.outputStream,
									false
								)
								while (!Thread.currentThread().isInterrupted)
									rtlSelector.sendRequest(selector.nextRequest().getOrThrow())
							} catch (_: IOException) {
							} catch (_: InterruptedException) {
							} catch (e: Exception) {
								localLogger.log(Level.WARNING, e) { "RTL operation problem" }
							} finally {
								countDown.countDown()
								ltr.interrupt()
							}
						}

						rtl.uncaughtExceptionHandler = StandardUncaughtExceptionHandler(localLogger)
						ltr.uncaughtExceptionHandler = StandardUncaughtExceptionHandler(localLogger)

						downgradeSelector.sendRequest(request)
						downgradeOutput.writeTo(pipeSocket.outputStream)

						countDown.await()
						pipeSocket.close()
					} catch (e: IOException) {
						localLogger.severe {
							"Host \"$host\" refused! [${e.javaClass.canonicalName}: ${e.localizedMessage}]"
						}
						selector.sendResponse(HTTPResponse(request, 503))
					} finally {
						sock.close()
						pipeSocket.close()
					}
				} else {
					localLogger.warning { "No route for host \"$host\"" }
					selector.sendResponse(HTTPResponse(request, 404))
				}
			} catch (_: IOException) {
			} finally {
				shutdown()
			}
		}.uncaughtExceptionHandler = StandardUncaughtExceptionHandler(localLogger)
	}
}