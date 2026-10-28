//! Per-poll allocation accounting for bounded, single-process comparisons.
//! Other tasks on the same executor are excluded while the measured future waits.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::pin::pin;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Counts {
    pub allocations: usize,
    pub bytes: usize,
    pub frees: usize,
}

thread_local! {
    static ACTIVE: Cell<Option<Counts>> = const { Cell::new(None) };
}

struct CountedSystem;

#[global_allocator]
static ALLOCATOR: CountedSystem = CountedSystem;

fn record(bytes: usize, free: bool) {
    let _ = ACTIVE.try_with(|slot| {
        if let Some(mut counts) = slot.get() {
            if free {
                counts.frees += 1;
            } else {
                counts.allocations += 1;
                counts.bytes += bytes;
            }
            slot.set(Some(counts));
        }
    });
}

unsafe impl GlobalAlloc for CountedSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            record(layout.size(), false);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            record(layout.size(), false);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let ptr = unsafe { System.realloc(ptr, layout, size) };
        if !ptr.is_null() {
            record(size, false);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record(0, true);
        unsafe { System.dealloc(ptr, layout) };
    }
}

struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        ACTIVE.with(|slot| slot.set(None));
    }
}

pub(crate) fn measure<T>(f: impl FnOnce() -> T) -> (T, Counts) {
    ACTIVE.with(|slot| {
        assert!(slot.get().is_none(), "nested allocation measurement");
        slot.set(Some(Counts::default()));
    });
    let reset = Reset;
    let result = f();
    let counts = ACTIVE.with(|slot| slot.replace(None).unwrap());
    drop(reset);
    (result, counts)
}

pub(crate) async fn measure_future<F: Future>(future: F) -> (F::Output, Counts) {
    let mut future = pin!(future);
    let mut total = Counts::default();
    let output = poll_fn(|cx| {
        let (result, counts) = measure(|| future.as_mut().poll(cx));
        total.allocations += counts.allocations;
        total.bytes += counts.bytes;
        total.frees += counts.frees;
        result
    })
    .await;
    (output, total)
}
