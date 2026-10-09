package org.fips.relaybench;

import static org.junit.Assert.*;
import static org.robolectric.Shadows.shadowOf;

import android.net.ConnectivityManager;
import android.net.IpPrefix;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.RouteInfo;
import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowNetwork;
import org.robolectric.util.ReflectionHelpers;
import org.robolectric.util.ReflectionHelpers.ClassParameter;

/** Exercise real path selection; Android owns only the network callback and process binding. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35)
public final class WifiBindingTest {
    private ConnectivityManager manager;
    private ConnectivityManager.NetworkCallback callback;
    private WifiBinding wifi;
    private final Network first = ShadowNetwork.newInstance(100);
    private final Network second = ShadowNetwork.newInstance(101);

    @Before public void setup() {
        manager = RuntimeEnvironment.getApplication().getSystemService(ConnectivityManager.class);
        wifi = new WifiBinding(RuntimeEnvironment.getApplication());
        callback = shadowOf(manager).getNetworkCallbacks().iterator().next();
    }

    @After public void close() { wifi.unbindAfterStop(); wifi.close(); }

    private static LinkAddress address(String value) {
        return ReflectionHelpers.callConstructor(LinkAddress.class, ClassParameter.from(String.class, value));
    }

    private static LinkProperties path(String address, String prefix) {
        LinkProperties properties = new LinkProperties();
        properties.setInterfaceName("wlan0");
        properties.setLinkAddresses(List.of(address(address)));
        IpPrefix subnet = ReflectionHelpers.callConstructor(IpPrefix.class, ClassParameter.from(String.class, prefix));
        properties.addRoute(ReflectionHelpers.callConstructor(RouteInfo.class,
            ClassParameter.from(IpPrefix.class, subnet), ClassParameter.from(InetAddress.class, null),
            ClassParameter.from(String.class, "wlan0")));
        return properties;
    }

    @Test public void changedAddressesRebindButDuplicateAndDnsCallbacksDoNot() throws Exception {
        AtomicInteger changes = new AtomicInteger();
        wifi.setListener(changes::incrementAndGet);
        LinkProperties properties = path("192.0.2.5/24", "192.0.2.0/24");
        callback.onLinkPropertiesChanged(first, properties);
        wifi.bind("192.0.2.1");
        assertFalse(wifi.refresh());
        assertEquals(first, manager.getBoundNetworkForProcess());
        properties.setDnsServers(List.of(InetAddress.getByName("192.0.2.1")));
        callback.onLinkPropertiesChanged(first, properties);
        assertEquals(1, changes.get());
        assertFalse(wifi.refresh());

        // Mutating a callback object must not mutate the saved bound path.
        properties.setLinkAddresses(List.of(address("192.0.2.6/24")));
        callback.onLinkPropertiesChanged(first, properties);
        assertEquals(2, changes.get());
        assertTrue(wifi.refresh());
        assertTrue("a failed native rebind remains retryable", wifi.refresh());
        wifi.rebound();
        assertFalse(wifi.refresh());
    }

    @Test public void lossRetainsBindingAndOnlyAnUnambiguousOnLinkWifiCanReplaceIt() throws Exception {
        callback.onLinkPropertiesChanged(first, path("192.0.2.5/24", "192.0.2.0/24"));
        wifi.bind("192.0.2.1");
        callback.onLinkPropertiesChanged(second, path("192.0.2.6/24", "192.0.2.0/24"));
        assertThrows(IllegalStateException.class, () -> wifi.refresh());
        assertEquals(first, manager.getBoundNetworkForProcess());
        callback.onLost(first);
        callback.onLinkPropertiesChanged(second, path("198.51.100.5/24", "0.0.0.0/0"));
        assertThrows(IllegalStateException.class, () -> wifi.refresh());
        assertEquals(first, manager.getBoundNetworkForProcess());
        callback.onLinkPropertiesChanged(second, path("192.0.2.6/24", "192.0.2.0/24"));
        assertTrue(wifi.refresh());
        assertEquals(second, manager.getBoundNetworkForProcess());
        wifi.rebound();
        wifi.unbindAfterStop();
        assertNull(manager.getBoundNetworkForProcess());
        assertFalse(wifi.refresh());
    }

    @Test public void oldOwnerCannotRemoveReplacementListener() {
        AtomicInteger firstCalls = new AtomicInteger();
        AtomicInteger secondCalls = new AtomicInteger();
        Runnable old = firstCalls::incrementAndGet;
        Runnable replacement = secondCalls::incrementAndGet;
        wifi.setListener(old);
        wifi.setListener(replacement);
        wifi.clearListener(old);
        callback.onLinkPropertiesChanged(first, path("192.0.2.5/24", "192.0.2.0/24"));
        assertEquals(0, firstCalls.get());
        assertEquals(1, secondCalls.get());
        wifi.clearListener(replacement);
        callback.onLost(first);
        assertEquals(1, secondCalls.get());
    }
}
