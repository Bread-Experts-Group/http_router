package org.bread_experts_group

import org.bread_experts_group.http.HTTPRequest
import org.bread_experts_group.http.HTTPResponse
import org.bread_experts_group.http.HTTPVersion
import org.bread_experts_group.stream.FailQuickInputStream
import java.io.IOException
import java.net.ServerSocket
import java.net.URISyntaxException
import java.util.logging.Logger

private val insecureLogger = Logger.getLogger("HTTP Routing, Insecure")

fun insecureOperation(
	insecureServerSocket: ServerSocket
) = Runnable {
	while (true) {
		insecureLogger.finer("Waiting for next socket")
		val sock = insecureServerSocket.accept()
		sock.keepAlive = true
		sock.soTimeout = 60000
		sock.setSoLinger(true, 2)
		Thread.ofVirtual().name("Routing-${sock.localSocketAddress}<${sock.remoteSocketAddress}").start {
			val localLogger = Logger.getLogger("${insecureLogger.name}.${sock.remoteSocketAddress}")
			try {
				localLogger.fine("Thread start")
				val fqIn = FailQuickInputStream(sock.inputStream)
				val request = try {
					HTTPRequest.read(fqIn)
				} catch (_: URISyntaxException) {
					HTTPResponse(400, HTTPVersion.HTTP_1_1)
						.write(sock.outputStream)
					return@start
				}
				val host = request.headers["Host"]
				if (host == null) {
					insecureLogger.warning("No host?")
					HTTPResponse(400, request.version)
						.write(sock.outputStream)
					return@start
				}
				HTTPResponse(
					308, request.version,
					mapOf(
						"Location" to "https://$host${request.path}",
						"Connection" to "close"
					)
				).write(sock.outputStream)
			} catch (_: FailQuickInputStream.EndOfStream) {
			} catch (e: IOException) {
				localLogger.warning { "IO failure encountered; ${e.localizedMessage}" }
			} finally {
				sock.close()
			}
		}
	}
}