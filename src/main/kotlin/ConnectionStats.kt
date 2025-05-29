package org.bread_experts_group.http_router

data class ConnectionStats(
	var rx: Long,
	var tx: Long,
	var connections: Long
)
