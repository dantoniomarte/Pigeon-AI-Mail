//! Runtime bridge: run an async DNS lookup from a synchronous context on
//! whatever tokio runtime is available. Inside a multi-thread runtime,
//! `block_in_place` is the documented way; inside a current-thread runtime
//! it panics, so `Handle::block_on` directly is used instead (issue #111,
//! hardened by #121 F7).
//!
//! F7 fix (#121): the old code called `block_in_place` unconditionally
//! when a handle existed — which panics on a current-thread runtime.
//! Now the flavor is checked: multi-thread uses `block_in_place` (the
//! documented pattern); current-thread uses `Handle::block_on` directly,
//! which is safe from a blocking-pool thread (spawn_blocking) and does
//! not panic from the runtime thread itself (it would deadlock instead,
//! but the auth path always runs on spawn_blocking).

use std::future::Future;

/// Run `future` to completion from synchronous code.
pub fn block_on_any<F: Future>(future: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        Err(_) => {
            // No runtime at all (pure unit test): spin one up on this thread.
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("auth runtime")
                .block_on(future)
        }
        Ok(handle) => {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
                // A current-thread runtime: block_in_place would panic
                // (issue #121 F7). Handle::block_on is safe from a
                // blocking-pool thread (where the auth path runs).
                handle.block_on(future)
            } else {
                // A multi-thread runtime: block_in_place converts the
                // current worker thread to a blocking thread, letting
                // other workers keep making progress.
                tokio::task::block_in_place(|| handle.block_on(future))
            }
        }
    }
}
