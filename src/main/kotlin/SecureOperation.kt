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
import org.bread_experts_group.stream.FailQuickInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.*
import java.nio.ByteBuffer
import java.nio.channels.AsynchronousCloseException
import java.nio.channels.ServerSocketChannel
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicLong
import java.util.function.BiFunction
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
			val dataIn = ByteBuffer.allocate(engine.session.applicationBufferSize)
			val dataOut = ByteBuffer.allocate(engine.session.applicationBufferSize)
			try {
				var handshakeStatus = engine.handshakeStatus
				while (
					handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED &&
					handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
				) when (handshakeStatus) {
					SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
						stats.rx.addAndGet(sock.read(tlsIn).toLong())
						tlsIn.flip()
						val result = engine.unwrap(tlsIn, dataIn)
						tlsIn.compact()
						if (result.status != SSLEngineResult.Status.OK) TODO(result.status.name)
						handshakeStatus = result.handshakeStatus
					}

					SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
						tlsOut.clear()
						val result = engine.wrap(dataOut, tlsOut)
						tlsOut.flip()
						stats.tx.addAndGet(sock.write(tlsOut).toLong())
						when (result.status) {
							SSLEngineResult.Status.OK -> {}
							SSLEngineResult.Status.BUFFER_OVERFLOW -> {
								tlsOut = ByteBuffer.allocate(engine.session.packetBufferSize)
							}

							else -> TODO(result.status.name)
						}
						handshakeStatus = result.handshakeStatus
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
			} catch (e: SSLHandshakeException) {
				localLogger.warning { "SSL Handshake exception; ${e.localizedMessage}" }
				if (sock.isOpen) {
					sock.shutdownInput()
					sock.shutdownOutput()
				}
				sock.close()
				return@start
			}
			val pipeSocket = Socket()
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
				dataIn.flip()
				val selector = HTTPProtocolSelector(
					when (engine.applicationProtocol) {
						"h2" -> HTTPVersion.HTTP_2
						"http/1.0" -> HTTPVersion.HTTP_1_0
						"http/0.9" -> HTTPVersion.HTTP_0_9
						else -> HTTPVersion.HTTP_1_1
					},
					object : InputStream() {
						override fun read(): Int {
							if (dataIn.hasRemaining()) return dataIn.get().toInt()
							if (!tlsIn.hasRemaining()) {
								tlsIn.clear()
								stats.rx.addAndGet(sock.read(tlsIn).toLong())
							}
							tlsIn.flip()
							while (tlsIn.hasRemaining()) {
								dataIn.clear()
								val result = engine.unwrap(tlsIn, dataIn)
								when (result.status) {
									SSLEngineResult.Status.OK -> {}
									SSLEngineResult.Status.CLOSED -> throw FailQuickInputStream.EndOfStream()
									else -> TODO(result.status.name)
								}
								dataIn.flip()
							}
							return dataIn.get().toInt()
						}
					},
					object : OutputStream() {
						override fun write(b: Int) {
							write(byteArrayOf(b.toByte()), 0, 1)
						}

						override fun write(b: ByteArray, off: Int, len: Int) {
							var tx = 0
							while (tx < len) {
								val chunkSize = min(dataOut.capacity(), len - tx)
								dataOut.clear()
								dataOut.put(b, off + tx, chunkSize)
								dataOut.flip()

								while (dataOut.hasRemaining()) {
									tlsOut.clear()
									val result = engine.wrap(dataOut, tlsOut)
									if (result.status != SSLEngineResult.Status.OK) TODO(result.status.name)
									tlsOut.flip()
									while (tlsOut.hasRemaining()) stats.tx.addAndGet(sock.write(tlsOut).toLong())
								}

								tx += chunkSize
							}
						}
					},
					true
				)
				val request: HTTPRequest = selector.nextRequest().getOrThrow()
				val host = if (reqNames.isNotEmpty()) {
					val sniHost = reqNames.firstOrNull { (redirectionTable[it] != null) || (routingTable[it] != null) }
					if (sniHost == null) throw SocketException()
					sniHost
				} else {
					val readHost = request.headers["Host"]
					if (readHost == null) {
						if (reqNames.isEmpty())
							selector.sendResponse(HTTPResponse(request, 400))
						throw SocketException()
					}
					readHost
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
							null, downgradeOutput,
							false
						)
						val countDown = CountDownLatch(2)
						var ltr: Thread? = null
						val rtl = Thread.ofVirtual().name(Thread.currentThread().name + ".RTL").start {
							try {
								val rtlSelector = HTTPProtocolSelector(
									HTTPVersion.HTTP_1_1,
									null, pipeSocket.outputStream,
									false
								)
								while (!Thread.currentThread().isInterrupted)
									rtlSelector.sendRequest(selector.nextRequest().getOrThrow())
							} catch (_: InterruptedException) {
							} catch (_: IOException) {
							} finally {
								countDown.countDown()
								ltr!!.interrupt()
							}
						}
						rtl.uncaughtExceptionHandler = StandardUncaughtExceptionHandler(localLogger)
						ltr = Thread.ofVirtual().name(Thread.currentThread().name + ".LTR").start {
							try {
								val ltrSelector = HTTPProtocolSelector(
									HTTPVersion.HTTP_1_1,
									pipeSocket.inputStream, OutputStream.nullOutputStream(),
									false
								)
								while (!Thread.currentThread().isInterrupted)
									selector.sendResponse(ltrSelector.nextResponse().getOrThrow())
							} catch (_: InterruptedException) {
							} catch (_: IOException) {
							} finally {
								countDown.countDown()
								rtl.interrupt()
							}
						}
						ltr.uncaughtExceptionHandler = StandardUncaughtExceptionHandler(localLogger)
						downgradeSelector.sendRequest(request)
						downgradeOutput.writeTo(pipeSocket.outputStream)
						countDown.await()
						sock.shutdownOutput()
						sock.shutdownInput()
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
			} catch (_: AsynchronousCloseException) {
			} catch (e: IOException) {
				localLogger.warning { "IO failure encountered; [${e.javaClass.canonicalName}] ${e.localizedMessage}" }
			} finally {
				if (sock.isOpen) {
					sock.shutdownInput()
					sock.shutdownOutput()
				}
				sock.close()
				pipeSocket.close()
				localLogger.info("Goodbye")
			}
		}.uncaughtExceptionHandler = StandardUncaughtExceptionHandler(localLogger)
	}
}