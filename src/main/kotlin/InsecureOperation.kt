package org.bread_experts_group

import org.bread_experts_group.http.HTTPRequest
import org.bread_experts_group.http.HTTPResponse
import org.bread_experts_group.socket.failquick.FailQuickInputStream
import org.bread_experts_group.socket.failquick.FailQuickOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.ServerSocket
import java.util.logging.Logger
import javax.net.ssl.SSLException

private val insecureLogger = Logger.getLogger("HTTP Routing, Insecure")

fun insecureOperation(
	insecureServerSocket: ServerSocket
) = Runnable {
	while (true) {
		val sock = insecureServerSocket.accept()
		val fqIn = FailQuickInputStream(sock.inputStream)
		val fqOut = FailQuickOutputStream(sock.outputStream)
		Thread.ofVirtual().name("Routing-${sock.localSocketAddress}<${sock.remoteSocketAddress}").start {
			try {
				val request = HTTPRequest.read(fqIn)
				val host = request.headers["Host"]
				if (host == null) {
					insecureLogger.warning("No host?")
					HTTPResponse(400, request.version, emptyMap(), "")
						.write(fqOut)
					return@start
				}
				HTTPResponse(
					308, request.version,
					mapOf(
						"Location" to "https://$host${request.path}"
					),
					""
				).write(fqOut)
			} catch (_: EOFException) {
			} catch (e: SSLException) {
				insecureLogger.warning { "SSL failure encountered; ${e.localizedMessage}" }
				sock.close()
			} catch (e: IOException) {
				insecureLogger.warning { "IO failure encountered; ${e.localizedMessage}" }
				sock.close()
			}
		}
	}
}