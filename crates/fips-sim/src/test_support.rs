pub(crate) fn run_large_stack_async_test<F, Fut>(name: &'static str, test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    run_large_stack_test(name, false, test);
}

pub(crate) fn run_large_stack_paused_async_test<F, Fut>(name: &'static str, test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    run_large_stack_test(name, true, test);
}

fn run_large_stack_test<F, Fut>(name: &'static str, start_paused: bool, test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    let handle = std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            let mut runtime = tokio::runtime::Builder::new_current_thread();
            runtime.enable_all().start_paused(start_paused);
            runtime
                .build()
                .expect("large-stack simulation test runtime")
                .block_on(test());
        })
        .expect("spawn large-stack simulation test");

    if let Err(panic) = handle.join() {
        std::panic::resume_unwind(panic);
    }
}
