package org.fips.relaybench;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.os.Bundle;
import android.provider.Settings;
import android.util.AtomicFile;
import android.util.Base64;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONObject;

/** Foreground test customer. Intents preview setup only; purchases require a button. */
public final class MainActivity extends Activity {
    private static final ExecutorService WORK = Executors.newSingleThreadExecutor();
    private final List<Button> buttons = new ArrayList<>();
    private WifiBinding wifi;
    private JSONObject profile;
    private String entryIp;
    private JSONObject state = new JSONObject();
    private JSONObject networkEvidence = new JSONObject();
    private long balance = -1;
    private boolean busy;
    private TextView status;
    private TextView details;
    private TextView message;
    private ProgressBar progress;
    private Button setup, funding, connect, buy, send, finish, stop, export;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        wifi = new WifiBinding(getApplicationContext());
        buildView();
        loadSetup(getIntent());
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        loadSetup(intent);
    }

    private void buildView() {
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(24), dp(24), dp(24), dp(24));
        content.setBackgroundColor(Color.rgb(250, 250, 247));
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(content);
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
            return insets;
        });
        setContentView(scroll);
        TextView title = text(content, 32);
        title.setTypeface(null, Typeface.BOLD);
        title.setText(R.string.app_title);
        text(content, 14).setText(R.string.subtitle);
        status = text(content, 22);
        status.setPadding(0, dp(24), 0, dp(8));
        details = text(content, 16);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setIndeterminate(true);
        progress.setVisibility(View.GONE);
        content.addView(progress);
        message = text(content, 14);
        message.setPadding(0, dp(12), 0, dp(12));
        setup = button(content, R.string.setup, () -> action("setup", true, () -> {
            call(new JSONObject().put("type", "setup").put("profile", profile));
            refresh();
        }));
        funding = button(content, R.string.load_funds, () -> action("import", true, () -> {
            JSONObject funds = new JSONObject(readPrivate("funding.json", 70_000));
            call(new JSONObject().put("type", "import").put("token", funds.getString("token")));
            if (!new File(getFilesDir(), "funding.json").delete()) throw new IllegalStateException("Funds loaded; funding file cleanup failed");
            refresh();
        }));
        connect = button(content, R.string.connect, () -> action("start", true, () -> { call(command("start")); refresh(); }));
        buy = button(content, R.string.buy, () -> action("buy", false, () -> { call(command("buy")); refresh(); }));
        send = button(content, R.string.send, () -> action("send", false, () -> {
            StringBuilder payload = new StringBuilder("FIPS Bench ").append(UUID.randomUUID()).append(' ');
            while (payload.length() < 1000) payload.append('x');
            call(new JSONObject().put("type", "send").put("payload", payload.toString()));
            refresh();
            showMessage(getString(R.string.queued));
        }));
        finish = button(content, R.string.finish, () -> action("finish", false, () -> {
            balance = call(command("finish")).getLong("balance_sat");
            wifi.unbindAfterStop();
            refresh(false);
        }));
        stop = button(content, R.string.stop, () -> action("stop", false, () -> {
            call(command("stop")); wifi.unbindAfterStop(); refresh(false);
        }));
        export = button(content, R.string.return_funds, () -> action("export", true, () -> {
            File idFile = new File(getFilesDir(), "return-id");
            if (!idFile.exists()) writePrivate("return-id", UUID.randomUUID().toString().replace("-", ""));
            JSONObject result = call(new JSONObject().put("type", "export")
                .put("id", readPrivate("return-id", 64)).put("amount_sat", balance));
            writePrivate("fund-return.json", result.toString());
            refresh();
            showMessage(getString(R.string.return_prepared));
        }));
        button(content, R.string.refresh, () -> action("status",
            state.optBoolean("configured") && !state.optBoolean("running"), () -> refresh()));
        button(content, R.string.wifi_settings, () -> startActivity(new Intent(Settings.ACTION_WIFI_SETTINGS)));
        text(content, 13).setText(R.string.billing_note);
        render();
    }

    private void loadSetup(Intent intent) {
        action("preview", false, () -> {
            state = call(command("status"));
            JSONObject candidate = null;
            if (state.optBoolean("configured")) {
                candidate = state.getJSONObject("profile");
            } else {
                profile = null;
                entryIp = null;
                String value = intent.getStringExtra("setup_profile");
                if (value == null && intent.getData() != null) {
                    String encoded = intent.getData().getQueryParameter("profile");
                    if (encoded != null && encoded.length() <= 8192) {
                        value = new String(Base64.decode(encoded, Base64.URL_SAFE | Base64.NO_WRAP), StandardCharsets.UTF_8);
                    }
                }
                if (value != null && value.length() <= 8192) candidate = new JSONObject(value);
            }
            if (candidate != null) {
                JSONObject checked = call(new JSONObject().put("type", "preview").put("profile", candidate));
                profile = checked.getJSONObject("profile");
                entryIp = checked.getString("entry_ip");
            }
            saveState();
        });
    }

    private interface Operation { void run() throws Exception; }

    private void action(String name, boolean bind, Operation operation) {
        if (busy) return;
        busy = true;
        message.setText("");
        render();
        WORK.execute(() -> {
            try {
                if (bind) {
                    if (entryIp == null) throw new IllegalStateException(getString(R.string.need_setup));
                    networkEvidence = wifi.bind(entryIp);
                }
                operation.run();
                writePrivate("last-action.json", new JSONObject().put("action", name).put("ok", true).toString());
            } catch (Exception error) {
                showMessage(error.getMessage() == null ? getString(R.string.failed) : error.getMessage());
                try { writePrivate("last-action.json", new JSONObject().put("action", name).put("error", error.toString()).toString()); }
                catch (Exception ignored) { /* Keep the original failure visible. */ }
            }
            runOnUiThread(() -> { if (!isDestroyed()) { busy = false; render(); } });
        });
    }

    private JSONObject call(JSONObject command) throws Exception {
        String result = NativeClient.execute(new File(getFilesDir(), "client").getAbsolutePath(), command.toString());
        if (result == null) throw new IllegalStateException(getString(R.string.failed));
        JSONObject response = new JSONObject(result);
        if (response.has("error")) throw new IllegalStateException(response.getString("error"));
        return response.getJSONObject("ok");
    }

    private static JSONObject command(String type) throws Exception { return new JSONObject().put("type", type); }
    private void refresh() throws Exception { refresh(true); }
    private void refresh(boolean wallet) throws Exception {
        state = call(command("status"));
        if (wallet && state.optBoolean("configured") && !state.optBoolean("running")) {
            balance = call(command("balance")).getLong("balance_sat");
        }
        saveState();
    }

    private void saveState() throws Exception {
        writePrivate("last-status.json", new JSONObject().put("customer", state)
            .put("wifi", networkEvidence).put("balance_sat", balance).toString());
    }

    private void render() {
        boolean configured = state.optBoolean("configured");
        boolean running = state.optBoolean("running");
        JSONObject relay = state.optJSONObject("relay");
        boolean paid = relay != null && relay.optJSONArray("purchases") != null && relay.optJSONArray("purchases").length() > 0;
        for (Button button : buttons) button.setEnabled(!busy);
        progress.setVisibility(busy ? View.VISIBLE : View.GONE);
        status.setText(running ? paid ? R.string.ready_to_send : R.string.connected : configured ? R.string.stopped : R.string.ready_to_setup);
        if (profile == null) {
            details.setText(R.string.need_setup);
        } else {
            String price = String.format(Locale.ROOT, "%.3f", profile.optLong("max_rate_msat_per_kib") / 1000.0);
            String description = getString(R.string.profile_details, profile.optLong("budget_sat"), price);
            if (running && relay != null) description += "\n" + getString(R.string.spending,
                profile.optLong("budget_sat") - relay.optLong("remaining_budget_sat"), relay.optLong("locked_sat"));
            else if (balance >= 0) description += "\n" + getString(R.string.balance, balance);
            details.setText(description);
        }
        setup.setVisibility(!configured && profile != null ? View.VISIBLE : View.GONE);
        funding.setVisibility(configured && !running && new File(getFilesDir(), "funding.json").exists() ? View.VISIBLE : View.GONE);
        connect.setVisibility(configured && !running ? View.VISIBLE : View.GONE);
        buy.setVisibility(running && !paid ? View.VISIBLE : View.GONE);
        send.setVisibility(running && paid ? View.VISIBLE : View.GONE);
        finish.setVisibility(running ? View.VISIBLE : View.GONE);
        stop.setVisibility(running ? View.VISIBLE : View.GONE);
        export.setVisibility(configured && !running && balance > 0 ? View.VISIBLE : View.GONE);
    }

    private TextView text(LinearLayout parent, int size) {
        TextView view = new TextView(this);
        view.setTextSize(size);
        view.setTextColor(Color.rgb(32, 40, 35));
        parent.addView(view);
        return view;
    }
    private Button button(LinearLayout parent, int title, Runnable action) {
        Button button = new Button(this);
        button.setText(title);
        button.setAllCaps(false);
        button.setMinHeight(dp(52));
        button.setOnClickListener(view -> action.run());
        parent.addView(button, new LinearLayout.LayoutParams(-1, -2));
        buttons.add(button);
        return button;
    }
    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private void showMessage(String value) { runOnUiThread(() -> { if (!isDestroyed()) message.setText(value); }); }

    private String readPrivate(String name, int limit) throws Exception {
        File file = new File(getFilesDir(), name);
        if (file.length() > limit) throw new IllegalStateException("Private input exceeds its limit");
        byte[] bytes = new AtomicFile(file).readFully();
        if (bytes.length > limit) throw new IllegalStateException("Private input exceeds its limit");
        return new String(bytes, StandardCharsets.UTF_8);
    }
    private void writePrivate(String name, String value) throws Exception {
        AtomicFile file = new AtomicFile(new File(getFilesDir(), name));
        FileOutputStream stream = null;
        try {
            stream = file.startWrite();
            stream.write(value.getBytes(StandardCharsets.UTF_8));
            file.finishWrite(stream);
        } catch (Exception error) { file.failWrite(stream); throw error; }
    }

    @Override protected void onStop() {
        super.onStop();
        WORK.execute(() -> {
            try {
                call(command("stop"));
                wifi.unbindAfterStop();
                refresh(false);
            } catch (Exception error) { showMessage(getString(R.string.stop_pending)); }
        });
    }
    @Override protected void onRestart() { super.onRestart(); loadSetup(getIntent()); }
    @Override protected void onDestroy() { wifi.close(); super.onDestroy(); }
}
