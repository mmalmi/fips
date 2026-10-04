package org.fips.relaybench;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Bundle;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ResultReceiver;
import java.util.concurrent.atomic.AtomicLong;
import org.json.JSONObject;

/** User-started lifetime for the native session; leaving the activity keeps it running. */
public final class RoutingService extends Service {
    static final String ACTION = "operation";
    static final String REPLY = "reply";
    static final int NOTIFICATION = 1;
    private static final String CHANNEL = "routing";
    private static final AtomicLong GENERATION = new AtomicLong();
    private final Handler main = new Handler(Looper.getMainLooper());
    private long generation;
    private int latestStart;
    private BenchClient client;
    private boolean stopped;

    @Override public void onCreate() {
        super.onCreate();
        generation = GENERATION.incrementAndGet();
        client = BenchClient.get(this);
        getSystemService(NotificationManager.class).createNotificationChannel(
            new NotificationChannel(CHANNEL, getString(R.string.routing_channel), NotificationManager.IMPORTANCE_LOW));
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        latestStart = startId;
        // Promote before queuing any native or wallet work, which may take time.
        startForeground(NOTIFICATION, notification(R.string.routing_active), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        String requested = intent == null ? null : intent.getStringExtra(ACTION);
        String operation = requested == null ? "stop" : requested;
        ResultReceiver reply = receiver(intent);
        BenchClient.WORK.execute(() -> {
            Bundle result = new Bundle();
            boolean end = false;
            try {
                JSONObject response;
                switch (operation) {
                    case "start":
                        stopped = false;
                        JSONObject status = client.call(BenchClient.command("status"));
                        response = new JSONObject();
                        if (!status.optBoolean("running")) {
                            JSONObject checked = client.call(new JSONObject().put("type", "preview")
                                .put("profile", status.getJSONObject("profile")));
                            response.put("wifi", client.wifi.bind(checked.getString("entry_ip")));
                            client.call(BenchClient.command("start"));
                        }
                        break;
                    case "stop":
                    case "finish":
                        response = client.call(BenchClient.command(operation));
                        client.wifi.unbindAfterStop();
                        stopped = true;
                        end = true;
                        break;
                    default: throw new IllegalArgumentException("Unknown routing operation");
                }
                result.putString("ok", response.toString());
            } catch (Exception error) {
                result.putString("error", error.getMessage() == null ? getString(R.string.failed) : error.getMessage());
                // A failed start or finish may still own a live native session.
                // Release its binding only after status confirms it is stopped.
                try {
                    if (!client.call(BenchClient.command("status")).optBoolean("running")) {
                        client.wifi.unbindAfterStop();
                        stopped = true;
                        end = true;
                    }
                } catch (Exception ignored) { /* Retain the binding and visible Stop action. */ }
            }
            boolean stopService = end;
            main.post(() -> {
                if (latestStart == startId) {
                    if (stopService) {
                        stopForeground(STOP_FOREGROUND_REMOVE);
                        stopSelfResult(startId);
                    } else if (result.containsKey("error")) {
                        getSystemService(NotificationManager.class).notify(NOTIFICATION, notification(R.string.stop_pending));
                    }
                }
                if (reply != null) reply.send(result.containsKey("error") ? 1 : 0, result);
            });
        });
        // Process death never silently restarts spending. The user reconnects.
        return START_NOT_STICKY;
    }

    @SuppressWarnings("deprecation")
    private static ResultReceiver receiver(Intent intent) {
        if (intent == null) return null;
        return Build.VERSION.SDK_INT >= 33 ? intent.getParcelableExtra(REPLY, ResultReceiver.class)
            : intent.getParcelableExtra(REPLY);
    }

    private Notification notification(int text) {
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), flags);
        PendingIntent stop = PendingIntent.getService(this, 1,
            new Intent(this, RoutingService.class).putExtra(ACTION, "stop"), flags);
        return new Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.bench_icon)
            .setContentTitle(getString(R.string.app_title)).setContentText(getString(text))
            .setContentIntent(open).setOngoing(true)
            .addAction(new Notification.Action.Builder(null, getString(R.string.stop), stop).build()).build();
    }

    @Override public void onDestroy() {
        // A replacement service may already be queued. Its new generation owns
        // the shared session; delayed cleanup must not stop that replacement.
        BenchClient.WORK.execute(() -> {
            if (GENERATION.get() != generation || stopped) return;
            try {
                client.call(BenchClient.command("stop"));
                client.wifi.unbindAfterStop();
            } catch (Exception ignored) { /* Keep a possibly live session bound to Wi-Fi. */ }
        });
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent intent) { return null; }
}
