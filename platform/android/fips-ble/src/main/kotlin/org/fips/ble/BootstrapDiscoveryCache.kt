package org.fips.ble

/** Bounds bootstrap reads and deduplicates completed values until invalidated. */
internal class BootstrapDiscoveryCache(private val capacity: Int = 64) {
    private val pending = mutableSetOf<String>()
    private val completed = linkedSetOf<String>()

    init {
        require(capacity > 0)
    }

    fun begin(token: String): Boolean {
        if (token in pending || token in completed || pending.size == capacity) return false
        return pending.add(token)
    }

    fun complete(token: String) {
        if (!pending.remove(token)) return
        completed.add(token)
        if (completed.size > capacity) completed.remove(completed.first())
    }

    fun invalidate(token: String) {
        pending.remove(token)
        completed.remove(token)
    }

    fun clear() {
        pending.clear()
        completed.clear()
    }
}
