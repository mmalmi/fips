package org.fips.relaybench;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.RouteInfo;
import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONObject;

/** Select an on-link Wi-Fi path before the shared native engine opens sockets. */
final class WifiBinding {
    private final ConnectivityManager manager;
    private final Map<Network, LinkProperties> networks = new LinkedHashMap<>();
    private final ConnectivityManager.NetworkCallback callback = new ConnectivityManager.NetworkCallback() {
        @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
            synchronized (networks) { networks.put(network, properties); }
        }
        @Override public void onLost(Network network) {
            synchronized (networks) { networks.remove(network); }
            // Keep any process binding: losing Wi-Fi must fail closed, not use cellular.
        }
    };

    WifiBinding(Context context) {
        manager = context.getSystemService(ConnectivityManager.class);
        manager.registerNetworkCallback(new NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback);
    }

    JSONObject bind(String validatedEntryIp) throws Exception {
        InetAddress entry = InetAddress.getByName(validatedEntryIp);
        Network selected = null;
        LinkProperties selectedProperties = null;
        synchronized (networks) {
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
        }
        if (selected == null || !manager.bindProcessToNetwork(selected)) {
            throw new IllegalStateException("Connect to the bench Wi-Fi first");
        }
        return new JSONObject().put("network_handle", selected.getNetworkHandle())
            .put("interface", selectedProperties.getInterfaceName()).put("entry_ip", validatedEntryIp);
    }

    void unbindAfterStop() { manager.bindProcessToNetwork(null); }
    void close() { manager.unregisterNetworkCallback(callback); }
}
