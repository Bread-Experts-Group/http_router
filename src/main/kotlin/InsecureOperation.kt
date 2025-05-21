package org.bread_experts_group.router

import org.bread_experts_group.http.HTTPRequest
import org.bread_experts_group.http.HTTPResponse
import org.bread_experts_group.http.HTTPVersion
import org.bread_experts_group.logging.ColoredLogger
import java.io.IOException
import java.net.ServerSocket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URISyntaxException

private val insecureLogger = ColoredLogger.newLogger("HTTP Routing, Insecure")

fun insecureOperation(
	insecureServerSocket: ServerSocket
) = Runnable {
	while (true) {
		insecureLogger.finer("Waiting for next socket")
		val sock = insecureServerSocket.accept()
		sock.keepAlive = true
		sock.soTimeout = 25000
		sock.setSoLinger(true, 2)
		Thread.ofVirtual().name("Routing-${sock.localSocketAddress}<${sock.remoteSocketAddress}").start {
			val localLogger = ColoredLogger.newLogger("${insecureLogger.name}.${sock.remoteSocketAddress}")
			try {
				localLogger.fine("Thread start")
				val request = try {
					HTTPRequest.read(sock.inputStream)
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
			} catch (_: SocketTimeoutException) {
			} catch (_: SocketException) {
			} catch (e: IOException) {
				localLogger.warning { "IO failure encountered; ${e.localizedMessage}" }
			} finally {
				sock.close()
			}
		}
	}
}