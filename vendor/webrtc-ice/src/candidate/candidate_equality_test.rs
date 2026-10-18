use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

use super::*;

struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

fn record_allocation() {
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(value) = count.get() {
            count.set(Some(value + 1));
        }
    });
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn allocations_in(action: impl FnOnce()) -> usize {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALLOCATIONS.with(|count| count.set(None));
        }
    }
    ALLOCATIONS.with(|count| count.set(Some(0)));
    let _reset = Reset;
    action();
    ALLOCATIONS.with(|count| count.get().unwrap())
}

fn candidate() -> CandidateBase {
    CandidateBase {
        network_type: AtomicU8::new(NetworkType::Udp4 as u8),
        candidate_type: CandidateType::ServerReflexive,
        address: "203.0.113.12".to_owned(),
        port: 5000,
        related_address: Some(CandidateRelatedAddress {
            address: "192.168.1.3".to_owned(),
            port: 6000,
        }),
        ..Default::default()
    }
}

fn previous_equality(left: &dyn Candidate, right: &dyn Candidate) -> bool {
    left.network_type() == right.network_type()
        && left.candidate_type() == right.candidate_type()
        && left.address() == right.address()
        && left.port() == right.port()
        && left.tcp_type() == right.tcp_type()
        && left.related_address() == right.related_address()
}

#[test]
fn test_candidate_equality_preserves_address_and_metadata_semantics() {
    let mut cases = vec![candidate(), candidate()];
    cases[1].id = "another candidate".to_owned();
    cases[1].component.store(2, Ordering::SeqCst);
    cases[1].priority_override = 123;
    cases[1].foundation_override = "other foundation".to_owned();
    *cases[1].resolved_addr.lock() = "203.0.113.99:5000".parse().unwrap();
    assert!(cases[0].equal(&cases[1]));

    let different = candidate();
    different
        .network_type
        .store(NetworkType::Tcp4 as u8, Ordering::SeqCst);
    cases.push(different);
    let mut different = candidate();
    different.candidate_type = CandidateType::Host;
    cases.push(different);
    let mut different = candidate();
    different.address = "host.local".to_owned();
    cases.push(different);
    let mut different = candidate();
    different.port += 1;
    cases.push(different);
    let mut different = candidate();
    different.tcp_type = TcpType::Passive;
    cases.push(different);
    let mut different = candidate();
    different.related_address.as_mut().unwrap().address = "192.168.1.4".to_owned();
    cases.push(different);
    let mut different = candidate();
    different.related_address.as_mut().unwrap().port += 1;
    cases.push(different);
    let mut different = candidate();
    different.related_address = None;
    cases.push(different);
    for address in [
        "2001:db8::1",
        "2001:0db8::1",
        "host.local",
        "HOST.local",
        "",
    ] {
        let mut different = candidate();
        different.address = address.to_owned();
        cases.push(different);
    }

    for left in &cases {
        for right in &cases {
            assert_eq!(left.equal(right), previous_equality(left, right));
        }
    }
}

#[test]
fn test_candidate_equality_does_not_allocate() {
    let left = candidate();
    let right = candidate();
    let allocations = allocations_in(|| {
        for _ in 0..100 {
            assert!(black_box(&left as &dyn Candidate).equal(black_box(&right)));
        }
    });
    assert_eq!(
        allocations, 0,
        "candidate comparisons must borrow address fields"
    );
}
