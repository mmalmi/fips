//! JNI owns one foreground app client; payment logic lives in fips-relay.
#![cfg(target_os = "android")]

use fips_relay::customer::{CustomerClient, CustomerCommand};
use jni::{
    JNIEnv,
    objects::{JClass, JString},
    sys::jstring,
};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Mutex};

struct Session {
    root: PathBuf,
    runtime: tokio::runtime::Runtime,
    client: CustomerClient,
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

fn dispatch(root: String, command: String) -> Result<Value, String> {
    if command.len() > 70_000 {
        return Err("customer request is too large".into());
    }
    let command: CustomerCommand =
        serde_json::from_str(&command).map_err(|_| "invalid customer request")?;
    let root = PathBuf::from(root);
    let mut state = SESSION
        .lock()
        .map_err(|_| "customer session requires an app restart")?;
    if state.is_none() {
        let client = CustomerClient::open(&root)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("fips-customer")
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        *state = Some(Session {
            root: root.clone(),
            runtime,
            client,
        });
    }
    let Session {
        root: saved,
        runtime,
        client,
    } = state.as_mut().unwrap();
    if saved != &root {
        return Err("customer storage cannot change within an app session".into());
    }
    runtime.block_on(client.execute(command))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_fips_relaybench_NativeClient_execute(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    root: JString<'_>,
    command: JString<'_>,
) -> jstring {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let root: String = env
            .get_string(&root)
            .map_err(|_| "invalid customer directory")?
            .into();
        let command: String = env
            .get_string(&command)
            .map_err(|_| "invalid customer command")?
            .into();
        dispatch(root, command)
    }))
    .unwrap_or_else(|_| Err("customer session failed; retained accounts require recovery".into()));
    let reply = match result {
        Ok(value) => json!({"ok":value}),
        Err(error) => json!({"error":error}),
    };
    env.new_string(reply.to_string())
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}
