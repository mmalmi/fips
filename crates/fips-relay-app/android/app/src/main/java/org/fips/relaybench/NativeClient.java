package org.fips.relaybench;

final class NativeClient {
    static { System.loadLibrary("fips_relay_app"); }
    private NativeClient() {}
    static native String execute(String directory, String command);
}
