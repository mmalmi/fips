//! Share bounded runtime sizing between the router and phone entry points.

/// Keep small routers from oversubscribing their CPUs, without increasing the
/// existing four-worker ceiling on larger hosts. Blocking wallet work uses
/// Tokio's separate blocking pool.
pub fn build(thread_name: &str) -> std::io::Result<tokio::runtime::Runtime> {
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(4);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name(thread_name)
        .enable_all()
        .build()
}
