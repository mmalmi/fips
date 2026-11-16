package org.fips.relaybench;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.RouteInfo;
import java.net.InetAddress;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.json.JSONObject;

/** Select an on-link Wi-Fi path before the shared native engine opens sockets. */
final class WifiBinding {
    private final ConnectivityManager manager;
    private final Map<Network, LinkProperties> networks = new LinkedHashMap<>();
    private String entryIp;
    private Network boundNetwork;
    private LinkProperties boundProperties;
    private boolean pendingRebind;
    private Runnable listener;
    private final ConnectivityManager.NetworkCallback callback = new ConnectivityManager.NetworkCallback() {
        @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
            Runnable changed;
            synchronized (WifiBinding.this) {
                LinkProperties prior = networks.put(network, snapshot(properties));
                changed = samePath(prior, properties) ? null : listener;
            }
            if (changed != null) changed.run();
        }
        @Override public void onLost(Network network) {
            Runnable changed;
            synchronized (WifiBinding.this) {
                changed = networks.remove(network) == null ? null : listener;
            }
            // Keep any process binding: losing Wi-Fi must fail closed, not use cellular.
            if (changed != null) changed.run();
        }
    };

    WifiBinding(Context context) {
        manager = context.getSystemService(ConnectivityManager.class);
        manager.registerNetworkCallback(new NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback);
    }

    synchronized void setListener(Runnable next) { listener = next; }
    synchronized void clearListener(Runnable owner) { if (listener == owner) listener = null; }

    synchronized JSONObject bind(String validatedEntryIp) throws Exception {
        select(validatedEntryIp);
        entryIp = validatedEntryIp;
        pendingRebind = false;
        return new JSONObject().put("network_handle", boundNetwork.getNetworkHandle())
            .put("interface", boundProperties.getInterfaceName()).put("entry_ip", validatedEntryIp);
    }

    synchronized boolean refresh() throws Exception {
        if (entryIp == null) return false;
        select(entryIp);
        return pendingRebind;
    }

    synchronized void rebound() { pendingRebind = false; }

    private void select(String validatedEntryIp) throws Exception {
        InetAddress entry = InetAddress.getByName(validatedEntryIp);
        Network selected = null;
        LinkProperties selectedProperties = null;
        for (Map.Entry<Network, LinkProperties> candidate : networks.entrySet()) {
            boolean onLink = false;
            for (RouteInfo route : candidate.getValue().getRoutes()) {
                InetAddress gateway = route.getGateway();
                if (!route.isDefaultRoute() && (gateway == null || gateway.isAnyLocalAddress())
                        && route.getDestination().contains(entry)) onLink = true;
            }
            if (onLink) {
                if (selected != null) throw new IllegalStateException("Multiple Wi-Fi networks reach the entry");
                selected = candidate.getKey();
                selectedProperties = candidate.getValue();
            }
        }
        if (selected == null) {
            throw new IllegalStateException("Connect to the bench Wi-Fi first");
        }
        if (selected.equals(boundNetwork) && samePath(boundProperties, selectedProperties)) return;
        if (!manager.bindProcessToNetwork(selected)) throw new IllegalStateException("Wi-Fi is no longer available");
        boundNetwork = selected;
        boundProperties = selectedProperties;
        pendingRebind = true;
    }

    private static LinkProperties snapshot(LinkProperties properties) {
        LinkProperties copy = new LinkProperties();
        copy.setInterfaceName(properties.getInterfaceName());
        copy.setLinkAddresses(properties.getLinkAddresses());
        for (RouteInfo route : properties.getRoutes()) copy.addRoute(route);
        return copy;
    }

    private static boolean samePath(LinkProperties left, LinkProperties right) {
        return left != null && right != null
            && Objects.equals(left.getInterfaceName(), right.getInterfaceName())
            && new HashSet<>(left.getLinkAddresses()).equals(new HashSet<>(right.getLinkAddresses()))
            && new HashSet<>(left.getRoutes()).equals(new HashSet<>(right.getRoutes()));
    }

    synchronized void unbindAfterStop() {
        manager.bindProcessToNetwork(null);
        entryIp = null;
        boundNetwork = null;
        boundProperties = null;
        pendingRebind = false;
    }
    void close() { manager.unregisterNetworkCallback(callback); }
}
