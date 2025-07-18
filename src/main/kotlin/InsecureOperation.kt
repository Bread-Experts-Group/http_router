package org.bread_experts_group.http_router

import org.bread_experts_group.StandardUncaughtExceptionHandler
import org.bread_experts_group.command_line.ArgumentContainer
import org.bread_experts_group.logging.ColoredHandler
import org.bread_experts_group.protocol.http.HTTPProtocolSelector
import org.bread_experts_group.protocol.http.HTTPResponse
import org.bread_experts_group.protocol.http.HTTPVersion
import java.io.IOException
import java.net.SocketException
import java.net.StandardSocketOptions
import java.nio.BufferUnderflowException
import java.nio.channels.AsynchronousCloseException
import java.nio.channels.ServerSocketChannel

fun insecureOperation(
	insecureServerSocket: ServerSocketChannel,
	@Suppress("unused") routingTable: Map<String, Int>,
	@Suppress("unused") redirectionTable: Map<String, Pair<String, Boolean>>,
	@Suppress("unused") arguments: ArgumentContainer
) {
	while (true) {
		val sock = insecureServerSocket.accept()
		sock.setOption(StandardSocketOptions.SO_KEEPALIVE, true)
		val selector = HTTPProtocolSelector(
			HTTPVersion.HTTP_1_1,
			sock,
			sock,
			true
		)
		val localLogger = ColoredHandler.newLogger("HTTP.${sock.remoteAddress}")
		Thread.ofVirtual().name("HTTP.${sock.remoteAddress}").start {
			try {
				while (true) {
					val request = selector.nextRequest().getOrThrow()
					val host = request.headers["host"]
					if (host == null) {
						selector.sendResponse(HTTPResponse(request, 400))
						continue
					}
					selector.sendResponse(
						HTTPResponse(
							request,
							308,
							mapOf(
								"location" to "https://$host${request.path}",
								"connection" to "close"
							)
						)
					)
				}
			} catch (_: BufferUnderflowException) {
			} catch (_: SocketException) {
			} catch (_: AsynchronousCloseException) {
			} catch (e: IOException) {
				localLogger.warning { "IO failure encountered; ${e.localizedMessage}" }
			} finally {
				sock.close()
			}
		}.uncaughtExceptionHandler = StandardUncaughtExceptionHandler(localLogger)
	}
}