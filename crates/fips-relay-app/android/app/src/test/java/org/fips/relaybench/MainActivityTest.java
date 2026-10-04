package org.fips.relaybench;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.robolectric.Shadows.shadowOf;

import android.content.Context;
import android.content.Intent;
import android.Manifest;
import android.app.Notification;
import android.app.Service;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.annotation.GraphicsMode;
import org.robolectric.annotation.Implementation;
import org.robolectric.annotation.Implements;
import org.robolectric.annotation.LooperMode;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.android.controller.ServiceController;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.util.ReflectionHelpers;

/** Real activity lifecycle and private files; the native wallet and Wi-Fi are isolated. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35, qualifiers = "w393dp-h852dp-xhdpi",
    instrumentedPackages = "org.fips.relaybench",
    shadows = {MainActivityTest.Wallet.class, MainActivityTest.Wifi.class})
@LooperMode(LooperMode.Mode.PAUSED)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
public final class MainActivityTest {
    @Before public void resetWallet() throws Exception {
        drain();
        // Robolectric replaces the Application between tests within one JVM.
        ReflectionHelpers.setStaticField(BenchClient.class, "instance", null);
        Wallet.balance = 16;
        Wallet.original = null;
        Wallet.latest = null;
        Wallet.exports = 0;
        Wallet.allowNewReturn = false;
        Wallet.failBalance = false;
        Wallet.running = false;
        Wallet.starts = 0;
        Wallet.stops = 0;
        Wallet.failStop = false;
        Wifi.binds = 0;
        Wifi.unbinds = 0;
    }

    @Test public void routingSurvivesScreenRecreationAndNotificationStopsIt() throws Exception {
        shadowOf(RuntimeEnvironment.getApplication()).grantPermissions(Manifest.permission.POST_NOTIFICATIONS);
        ActivityController<MainActivity> screen = Robolectric.buildActivity(MainActivity.class).setup();
        MainActivity activity = screen.get();
        settle(activity);
        Button connect = ReflectionHelpers.getField(activity, "connect");
        connect.performClick();
        Intent request = shadowOf(RuntimeEnvironment.getApplication()).getNextStartedService();
        assertNotNull(request);
        ServiceController<RoutingService> owner = Robolectric.buildService(RoutingService.class, request).create();
        RoutingService service = owner.get();
        assertEquals(Service.START_NOT_STICKY, service.onStartCommand(request, 0, 1));
        settle(activity);
        assertTrue(Wallet.running);
        assertEquals(1, Wallet.starts);
        assertEquals(1, Wifi.binds);
        Notification notice = shadowOf(service).getLastForegroundNotification();
        assertNotNull(notice);
        assertTrue((notice.flags & Notification.FLAG_ONGOING_EVENT) != 0);
        capture(activity, "routing-running");

        screen.pause().stop().destroy();
        drain();
        assertTrue(Wallet.running);
        assertEquals(0, Wallet.stops);
        assertEquals(0, Wifi.unbinds);
        screen = Robolectric.buildActivity(MainActivity.class).setup();
        activity = screen.get();
        settle(activity);
        assertEquals(1, Wallet.starts);
        assertEquals(View.VISIBLE, ((Button) ReflectionHelpers.getField(activity, "stop")).getVisibility());

        notice.actions[0].actionIntent.send();
        Intent stop = shadowOf(RuntimeEnvironment.getApplication()).getNextStartedService();
        assertNotNull(stop);
        service.onStartCommand(stop, 0, 2);
        drain();
        assertFalse(Wallet.running);
        assertEquals(1, Wallet.stops);
        assertEquals(1, Wifi.unbinds);
        assertTrue(shadowOf(service).isStoppedBySelf());
        owner.destroy();
        screen.pause().stop().destroy();
        drain();
        assertEquals("destruction must not repeat a confirmed stop", 1, Wallet.stops);
    }

    @Test public void failedStopRetainsServiceAndBindingAndDestructionStopsTheSession() throws Exception {
        Intent start = new Intent(RuntimeEnvironment.getApplication(), RoutingService.class)
            .putExtra(RoutingService.ACTION, "start");
        ServiceController<RoutingService> owner = Robolectric.buildService(RoutingService.class, start).create();
        RoutingService service = owner.get();
        service.onStartCommand(start, 0, 1);
        drain();
        assertTrue(Wallet.running);
        Wallet.failStop = true;
        service.onStartCommand(new Intent(start).putExtra(RoutingService.ACTION, "stop"), 0, 2);
        drain();
        assertTrue(Wallet.running);
        assertFalse(shadowOf(service).isStoppedBySelf());
        assertEquals(0, Wifi.unbinds);
        owner.destroy();
        drain();
        assertFalse(Wallet.running);
        assertEquals(2, Wallet.stops);
        assertEquals(1, Wifi.unbinds);
    }

    @Test public void notificationPermissionIsRequiredBeforeConnecting() throws Exception {
        ActivityController<MainActivity> screen = Robolectric.buildActivity(MainActivity.class).setup();
        MainActivity activity = screen.get();
        settle(activity);
        Button connect = ReflectionHelpers.getField(activity, "connect");
        connect.performClick();
        activity.onRequestPermissionsResult(32, new String[] {Manifest.permission.POST_NOTIFICATIONS},
            new int[] {android.content.pm.PackageManager.PERMISSION_DENIED});
        drain();
        assertEquals(0, Wallet.starts);
        assertFalse(Wallet.running);
        assertEquals(null, shadowOf(RuntimeEnvironment.getApplication()).getNextStartedService());
        screen.pause().stop().destroy();
        drain();
    }

    @Test public void delayedServiceCleanupCannotStopItsReplacement() throws Exception {
        Intent start = new Intent(RuntimeEnvironment.getApplication(), RoutingService.class)
            .putExtra(RoutingService.ACTION, "start");
        ServiceController<RoutingService> first = Robolectric.buildService(RoutingService.class, start).create();
        first.get().onStartCommand(start, 0, 1);
        drain();
        CountDownLatch release = new CountDownLatch(1);
        BenchClient.WORK.submit(() -> { assertTrue(release.await(10, TimeUnit.SECONDS)); return null; });
        ServiceController<RoutingService> replacement;
        try {
            first.destroy();
            replacement = Robolectric.buildService(RoutingService.class, start).create();
            replacement.get().onStartCommand(start, 0, 1);
        } finally { release.countDown(); }
        drain();
        assertTrue(Wallet.running);
        assertEquals(1, Wallet.starts);
        assertEquals(0, Wallet.stops);
        assertEquals(0, Wifi.unbinds);
        replacement.destroy();
        drain();
        assertEquals(1, Wallet.stops);
        assertEquals(1, Wifi.unbinds);
    }

    @Test public void interruptedReturnKeepsItsRequestAndRemainsRetryableAfterRestart() throws Exception {
        ActivityController<MainActivity> controller = Robolectric.buildActivity(MainActivity.class).setup();
        MainActivity activity = controller.get();
        settle(activity);
        tap(activity, R.string.refresh);
        Button export = ReflectionHelpers.getField(activity, "export");
        assertEquals(View.VISIBLE, export.getVisibility());
        export.performClick();
        settle(activity);
        assertEquals(1, Wallet.exports);
        assertEquals(0, Wallet.balance);

        // Recreate the activity and refresh the now-empty wallet before retrying.
        controller.pause().stop().destroy();
        settle(activity);
        controller = Robolectric.buildActivity(MainActivity.class).setup();
        activity = controller.get();
        settle(activity);
        export = ReflectionHelpers.getField(activity, "export");
        assertEquals("retry is available before refreshing the balance", View.VISIBLE, export.getVisibility());
        tap(activity, R.string.refresh);
        export = ReflectionHelpers.getField(activity, "export");
        assertEquals("a pending return remains available at zero balance", View.VISIBLE, export.getVisibility());
        capture(activity, "return-pending");
        // AtomicFile must also recover the saved request from its backup.
        File summary = new File(activity.getFilesDir(), "fund-return.json");
        Files.move(summary.toPath(), new File(activity.getFilesDir(), "fund-return.json.bak").toPath());
        export.performClick();
        settle(activity);
        assertEquals(2, Wallet.exports);
        assertEquals(1, Wallet.original.getLong("id"));
        assertEquals(Wallet.original.getLong("id"), Wallet.latest.getLong("id"));
        assertEquals(Wallet.original.getLong("amount_sat"), Wallet.latest.getLong("amount_sat"));
        JSONObject completed = new JSONObject(new String(Files.readAllBytes(
            new File(activity.getFilesDir(), "fund-return.json").toPath()), StandardCharsets.UTF_8));
        assertEquals(16, completed.getLong("amount_sat"));
        assertEquals("original-operation", completed.getString("operation_id"));
        assertEquals(Wallet.original.getString("id"), completed.getString("id"));
        assertEquals(0, Wallet.balance);
        assertEquals(View.GONE, export.getVisibility());
        capture(activity, "return-completed");

        // New funds use a new request; a failed balance refresh must not repeat that spend.
        Wallet.balance = 9;
        Wallet.allowNewReturn = true;
        tap(activity, R.string.refresh);
        export.performClick();
        settle(activity);
        assertEquals(3, Wallet.exports);
        assertEquals(2, Wallet.latest.getLong("id"));
        assertEquals(9, Wallet.latest.getLong("amount_sat"));
        assertEquals(0, Wallet.balance);
        byte[] saved = Files.readAllBytes(summary.toPath());
        JSONObject next = new JSONObject(new String(saved, StandardCharsets.UTF_8));
        assertEquals("next-operation", next.getString("operation_id"));
        assertEquals(View.VISIBLE, export.getVisibility());
        export.performClick();
        settle(activity);
        assertEquals(3, Wallet.exports);
        assertEquals(View.GONE, export.getVisibility());
        assertArrayEquals(saved, Files.readAllBytes(summary.toPath()));
        controller.pause().stop().destroy();
        settle(activity);
    }

    @Test public void incompleteReturnEvidenceIsRetainedWithoutAnotherExport() throws Exception {
        ActivityController<MainActivity> controller = Robolectric.buildActivity(MainActivity.class).setup();
        MainActivity activity = controller.get();
        settle(activity);
        tap(activity, R.string.refresh);
        String id = "1";
        String[][] evidence = {
            {"fund-return.json", "{"},
            {"fund-return.json", "{\"id\":\"1\",\"amount_sat\":16}"},
            {"fund-return.json", "{\"id\":0,\"amount_sat\":16}"},
            {"fund-return.json", "{\"id\":9223372036854775807,\"amount_sat\":16,\"path\":\"saved\",\"operation_id\":\"saved\"}"},
            {"fund-return.json", "{\"id\":" + id + ",\"amount_sat\":1.5}"},
            {"fund-return.json", "{\"id\":" + id + ",\"amount_sat\":16,\"path\":\"incomplete\"}"},
            {"fund-return.json.new", "{\"id\":" + id + ",\"amount_sat\":16}"},
            {"return-id", id}
        };
        for (String[] entry : evidence) {
            File file = new File(activity.getFilesDir(), entry[0]);
            byte[] bytes = entry[1].getBytes(StandardCharsets.UTF_8);
            Files.write(file.toPath(), bytes);
            Button export = ReflectionHelpers.getField(activity, "export");
            export.performClick();
            settle(activity);
            assertEquals(0, Wallet.exports);
            assertEquals(16, Wallet.balance);
            assertArrayEquals(bytes, Files.readAllBytes(file.toPath()));
            assertTrue(file.delete());
        }
        controller.pause().stop().destroy();
        settle(activity);
    }

    private static void settle(MainActivity activity) throws Exception {
        drain();
        assertFalse((Boolean) ReflectionHelpers.getField(activity, "busy"));
    }

    private static void drain() throws Exception {
        // Service completion posts a UI refresh back onto the same worker.
        for (int i = 0; i < 3; i++) {
            BenchClient.WORK.submit(() -> {}).get(10, TimeUnit.SECONDS);
            shadowOf(Looper.getMainLooper()).idle();
        }
    }

    private static void tap(MainActivity activity, int text) throws Exception {
        Button button = findButton(activity.getWindow().getDecorView(), activity.getString(text));
        assertNotNull(button);
        assertEquals(View.VISIBLE, button.getVisibility());
        assertTrue(button.performClick());
        settle(activity);
    }

    private static Button findButton(View view, String text) {
        if (view instanceof Button && ((Button) view).getText().toString().equals(text)) return (Button) view;
        if (view instanceof android.view.ViewGroup) {
            android.view.ViewGroup group = (android.view.ViewGroup) view;
            for (int i = 0; i < group.getChildCount(); i++) {
                Button button = findButton(group.getChildAt(i), text);
                if (button != null) return button;
            }
        }
        return null;
    }

    private static void capture(MainActivity activity, String name) throws Exception {
        String directory = System.getProperty("fips.ui.evidence.dir");
        if (directory == null) return;
        View view = activity.getWindow().getDecorView();
        view.measure(View.MeasureSpec.makeMeasureSpec(786, View.MeasureSpec.EXACTLY),
            View.MeasureSpec.makeMeasureSpec(1704, View.MeasureSpec.EXACTLY));
        view.layout(0, 0, 786, 1704);
        Bitmap bitmap = Bitmap.createBitmap(786, 1704, Bitmap.Config.ARGB_8888);
        view.draw(new Canvas(bitmap));
        try (FileOutputStream file = new FileOutputStream(new File(directory, name + ".png"))) {
            assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, file));
        }
        bitmap.recycle();
    }

    @Implements(value = NativeClient.class, isInAndroidSdk = false)
    public static final class Wallet {
        static long balance;
        static JSONObject original;
        static JSONObject latest;
        static int exports;
        static boolean allowNewReturn;
        static boolean failBalance;
        static boolean running;
        static int starts;
        static int stops;
        static boolean failStop;
        @Implementation protected static void __staticInitializer__() {}
        @Implementation protected static String execute(String directory, String encoded) throws Exception {
            JSONObject command = new JSONObject(encoded);
            JSONObject profile = new JSONObject().put("budget_sat", 128).put("max_rate_msat_per_kib", 8192);
            JSONObject result;
            switch (command.getString("type")) {
                case "status": result = new JSONObject().put("configured", true).put("running", running).put("profile", profile); break;
                case "preview": result = new JSONObject().put("profile", profile).put("entry_ip", "127.0.0.1"); break;
                case "balance":
                    if (failBalance) {
                        failBalance = false;
                        return new JSONObject().put("error", "Balance reply was interrupted").toString();
                    }
                    result = new JSONObject().put("balance_sat", balance); break;
                case "start": starts++; running = true; result = new JSONObject(); break;
                case "stop":
                    stops++;
                    if (failStop) {
                        failStop = false;
                        return new JSONObject().put("error", "Stop is still pending").toString();
                    }
                    running = false; result = new JSONObject(); break;
                case "export":
                    exports++;
                    latest = command;
                    JSONObject saved = new JSONObject(new String(Files.readAllBytes(
                        new File(new File(directory).getParentFile(), "fund-return.json").toPath()), StandardCharsets.UTF_8));
                    if (!(command.get("id") instanceof Integer || command.get("id") instanceof Long)
                        || saved.getLong("id") != command.getLong("id")
                        || saved.getLong("amount_sat") != command.getLong("amount_sat")) {
                        return new JSONObject().put("error", "Export request was not saved").toString();
                    }
                    if (original == null) {
                        original = command;
                        balance -= command.getLong("amount_sat");
                        return new JSONObject().put("error", "Export reply was interrupted").toString();
                    }
                    if (!original.getString("id").equals(command.getString("id"))
                        || original.getLong("amount_sat") != command.getLong("amount_sat")) {
                        if (allowNewReturn && !original.getString("id").equals(command.getString("id"))) {
                            balance -= command.getLong("amount_sat");
                            failBalance = true;
                            result = new JSONObject().put("path", new File(directory, "next-export.json").getPath())
                                .put("amount_sat", command.getLong("amount_sat")).put("operation_id", "next-operation");
                            break;
                        }
                        return new JSONObject().put("error", "Export terms changed").toString();
                    }
                    result = new JSONObject().put("path", new File(directory, "original-export.json").getPath())
                        .put("amount_sat", original.getLong("amount_sat")).put("operation_id", "original-operation");
                    break;
                default: throw new AssertionError("unexpected customer command");
            }
            return new JSONObject().put("ok", result).toString();
        }
    }

    @Implements(value = WifiBinding.class, isInAndroidSdk = false)
    public static final class Wifi {
        static int binds;
        static int unbinds;
        @Implementation protected void __constructor__(Context context) {}
        @Implementation protected JSONObject bind(String address) { binds++; return new JSONObject(); }
        @Implementation protected void unbindAfterStop() { unbinds++; }
        @Implementation protected void close() {}
    }
}
