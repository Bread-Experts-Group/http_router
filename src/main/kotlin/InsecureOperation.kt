package org.bread_experts_group

import org.bread_experts_group.http.HTTPRequest
import org.bread_experts_group.http.HTTPResponse
import org.bread_experts_group.http.HTTPVersion
import java.io.EOFException
import java.io.IOException
import java.net.ServerSocket
import java.net.URISyntaxException
import java.util.logging.Logger
import javax.net.ssl.SSLException

private val insecureLogger = Logger.getLogger("HTTP Routing, Insecure")

fun insecureOperation(
	insecureServerSocket: ServerSocket
) = Runnable {
	while (true) {
		val sock = insecureServerSocket.accept()
		Thread.ofVirtual().name("Routing-${sock.localSocketAddress}<${sock.remoteSocketAddress}").start {
			try {
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
			} catch (_: EOFException) {
			} catch (e: SSLException) {
				insecureLogger.warning { "SSL failure encountered; ${e.localizedMessage}" }
			} catch (e: IOException) {
				insecureLogger.warning { "IO failure encountered; ${e.localizedMessage}" }
			}
			sock.close()
		}
	}
}