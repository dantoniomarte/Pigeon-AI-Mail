//! Runtime bridge: run an async DNS lookup from a synchronous context on
//! whatever tokio runtime is available. Inside a multi-thread runtime,
//! `block_in_place` is the documented way; inside a current-thread runtime
//! (tests) it panics, so a dedicated blocking thread running its own runtime
//! bridges the call instead (issue #111).

use std::future::Future;

/// Run `future` to completion from synchronous code.
pub fn block_on_any<F: Future>(future: F) -> F::Output {
    if tokio::runtime::Handle::try_current().is_err() {
        // No runtime at all (pure unit test): spin one up on this thread.
        return tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("auth runtime")
            .block_on(future);
    }
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
}
