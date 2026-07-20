package org.fips.ble

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BootstrapDiscoveryCacheTest {
    @Test
    fun connectionFailureMakesACompletedBootstrapEligibleForRefresh() {
        val cache = BootstrapDiscoveryCache()
        val peer = "peer"

        assertTrue(cache.begin(peer))
        assertFalse(cache.begin(peer))
        cache.complete(peer)
        assertFalse(cache.begin(peer))

        cache.invalidate(peer)

        assertTrue(cache.begin(peer))
    }

    @Test
    fun completedBootstrapCacheIsBounded() {
        val cache = BootstrapDiscoveryCache(capacity = 2)

        assertTrue(cache.begin("a"))
        cache.complete("a")
        assertTrue(cache.begin("b"))
        cache.complete("b")
        assertTrue(cache.begin("c"))
        cache.complete("c")
        assertTrue(cache.begin("a"))
    }

    @Test
    fun pendingBootstrapReadsAreBoundedWithoutEviction() {
        val cache = BootstrapDiscoveryCache(capacity = 2)

        assertTrue(cache.begin("a"))
        assertTrue(cache.begin("b"))
        assertFalse(cache.begin("c"))
        assertFalse(cache.begin("a"))

        cache.invalidate("a")

        assertTrue(cache.begin("c"))
    }
}
