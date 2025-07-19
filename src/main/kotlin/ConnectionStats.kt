package org.bread_experts_group.http_router

import org.bread_experts_group.formatMetric
import java.util.concurrent.atomic.AtomicLong

data class ConnectionStats(
	var requests: AtomicLong = AtomicLong(),
	var responses: AtomicLong = AtomicLong(),
	var rx: AtomicLong = AtomicLong(),
	var tx: AtomicLong = AtomicLong(),
	var connections: Long = 0
) {
	override fun toString(): String = "[#$connections ($requests ↓, $responses ↑) " +
			"(${rx.toDouble().formatMetric()}B ↓, ${tx.toDouble().formatMetric()}B ↑)]"
}