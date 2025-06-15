package org.bread_experts_group.http_router

import java.util.concurrent.atomic.AtomicLong

data class ConnectionStats(
	var rx: AtomicLong,
	var tx: AtomicLong,
	var connections: Long
)
