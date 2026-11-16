package org.fips.relaybench;

import android.content.Context;
import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONObject;

/** One serialized native session and Wi-Fi binding per process, independent of screens. */
final class BenchClient {
    static final ExecutorService WORK = Executors.newSingleThreadExecutor();
    private static BenchClient instance;
    private final Context context;
    final WifiBinding wifi;

    private BenchClient(Context context) {
        this.context = context.getApplicationContext();
        wifi = new WifiBinding(this.context);
    }

    static synchronized BenchClient get(Context context) {
        if (instance == null) instance = new BenchClient(context);
        return instance;
    }

    JSONObject call(JSONObject command) throws Exception {
        String result = NativeClient.execute(new File(context.getFilesDir(), "client").getAbsolutePath(), command.toString());
        if (result == null) throw new IllegalStateException(context.getString(R.string.failed));
        JSONObject response = new JSONObject(result);
        if (response.has("error")) throw new IllegalStateException(response.getString("error"));
        return response.getJSONObject("ok");
    }

    static JSONObject command(String type) throws Exception { return new JSONObject().put("type", type); }
}
