package bread_experts_group

import bread_experts_group.http.HTTPRequest
import bread_experts_group.http.HTTPResponse
import java.io.IOException
import java.net.ServerSocket
import javax.net.ssl.SSLException

fun insecureOperation(
	insecureServerSocket: ServerSocket
) = Runnable {
	while (true) {
		val sock = insecureServerSocket.accept()
		Thread.ofVirtual().name("Routing-${sock.localSocketAddress}<${sock.remoteSocketAddress}").start {
			try {
				val request = HTTPRequest.read(sock.inputStream)
				val host = request.headers["Host"]
				if (host == null) {
					info("No host?")
					HTTPResponse(400, request.version, emptyMap(), "")
						.write(sock.outputStream)
					return@start
				}
				HTTPResponse(
					308, request.version,
					mapOf(
						"Location" to "https://$host${request.path}"
					),
					""
				).write(sock.outputStream)
			} catch (e: SSLException) {
				warn("SSL failure encountered; ${e.localizedMessage}")
				sock.close()
			} catch (e: IOException) {
				warn("IO failure encountered; ${e.localizedMessage}")
				sock.close()
			}
		}
	}
}