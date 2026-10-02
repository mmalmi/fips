use super::measured;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};

#[tokio::test]
async fn measurement_preserves_real_pending_wakeup_and_output() {
    let mut polls = 0;
    let future = poll_fn(|cx| {
        polls += 1;
        if polls == 1 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(37)
        }
    });
    let (value, observed) = measured(true, future).await;
    assert_eq!(value, 37);
    assert_eq!(polls, 2);
    assert_eq!((observed.polls, observed.pending), (2, 1));
    let (value, unmeasured) = measured(false, std::future::ready(41)).await;
    assert_eq!(value, 41);
    assert_eq!((unmeasured.polls, unmeasured.pending), (0, 0));
}

struct Held(Arc<AtomicBool>);

impl Future for Held {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn measurement_cancellation_drops_the_original_future() {
    let dropped = Arc::new(AtomicBool::new(false));
    {
        let mut future = pin!(measured(true, Held(dropped.clone())));
        assert!(futures::poll!(&mut future).is_pending());
        assert!(!dropped.load(Ordering::SeqCst));
    }
    assert!(dropped.load(Ordering::SeqCst));
}
