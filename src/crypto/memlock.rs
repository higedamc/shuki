//! Best-effort memory locking so secrets stay out of swap (issue #1).
//!
//! Zeroize-on-drop (used throughout shuki) wipes secrets at end-of-life but
//! does nothing while they are alive: the kernel may swap the pages out at
//! any point. This module adds the missing half:
//!
//! - [`LockedBox`]: page-locked heap cell for long-lived, fixed-size key
//!   material (conversation keys, tag keys). Backed by `memsec::malloc`,
//!   which gives the value its own guard-paged, canaried, `mlock`ed pages —
//!   so dropping one secret can never unlock another one sharing a page.
//! - [`LockedString`]: an immutable `String` whose existing heap buffer is
//!   `mlock`ed/`VirtualLock`ed in place (used by
//!   [`crate::domain::SecretField`]). Page-granular: unlocking one buffer on
//!   drop may unpin a neighbour that happens to share the page, which is why
//!   long-lived keys use [`LockedBox`] instead.
//!
//! # Failure policy
//!
//! Locking is BEST EFFORT. `RLIMIT_MEMLOCK` exhaustion, containers, seccomp,
//! or unusual kernels (e.g. Qubes) can all make it fail; shuki then keeps
//! working with plain (still zeroized) memory and emits a single
//! process-wide `tracing::warn!`.
//!
//! # Known limits (also in the README)
//!
//! - Hibernation (suspend-to-disk) writes even locked pages to disk; only
//!   encrypted swap covers that threat model.
//! - Transient stack/register copies made while a key is moved around, and
//!   temporary buffers inside the `nostr` crate, are not covered.

// The single sanctioned unsafe module in the crate (see lib.rs): page
// locking is FFI by nature. Every unsafe block carries its safety argument.
#![allow(unsafe_code)]

use core::mem::{align_of, size_of};
use core::ops::Deref;
use core::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroize;

static LOCK_FAILURE_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_lock_failed() {
    if !LOCK_FAILURE_WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            "mlock/VirtualLock unavailable; secrets remain zeroize-on-drop only and \
             may reach swap (check RLIMIT_MEMLOCK / container / sandbox settings)"
        );
    }
}

/// Best-effort page lock of `len` bytes at `ptr` (no-op for `len == 0`).
/// Returns whether the region is now pinned. Failure only warns (once per
/// process); the caller keeps working with unlocked memory.
///
/// # Safety
///
/// `ptr..ptr+len` must be a live allocation owned by the caller for as long
/// as the lock is held (mlock itself never dereferences the pointer).
unsafe fn lock_region(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    let locked = unsafe { memsec::mlock(ptr as *mut u8, len) };
    if !locked {
        warn_lock_failed();
    }
    locked
}

/// Zeroize and unlock a region previously pinned by [`lock_region`].
///
/// # Safety
///
/// The region must be live and writable through `ptr`'s provenance:
/// `memsec::munlock` zeroizes the bytes with plain writes before unlocking,
/// so `ptr` must carry write permission (derive it from `as_mut_ptr`, after
/// any `&mut` use of the buffer).
unsafe fn unlock_region(ptr: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        memsec::munlock(ptr, len);
    }
}

/// An immutable `String` whose heap buffer is page-locked in place for its
/// lifetime (best effort) and zeroized on drop.
///
/// Locking in place is page-granular and not reference-counted: dropping
/// one `LockedString` may unpin a neighbour's buffer sharing the same page.
/// That is accepted for this best-effort tier — long-lived keys use
/// [`LockedBox`]'s dedicated pages instead. `locked` therefore means "was
/// pinned at construction", not a lifetime guarantee.
pub(crate) struct LockedString {
    value: String,
    locked: bool,
}

impl LockedString {
    /// INVARIANT upheld by this type: `value` is never mutated after
    /// construction, so the buffer is never reallocated while locked.
    pub(crate) fn new(value: String) -> Self {
        // SAFETY: `value`'s buffer is a live allocation owned by `self`
        // until drop, and the no-mutation invariant keeps it in place.
        let locked = unsafe { lock_region(value.as_ptr(), value.capacity()) };
        Self { value, locked }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }
}

impl Drop for LockedString {
    fn drop(&mut self) {
        // Wipes the full capacity in place (no reallocation).
        self.value.zeroize();
        if self.locked {
            let cap = self.value.capacity();
            let ptr = self.value.as_mut_ptr();
            // SAFETY: buffer is live until the String drops after this body;
            // `ptr` was derived from `as_mut_ptr` after every other use of
            // the buffer, so the writes inside munlock stay within
            // provenance.
            unsafe { unlock_region(ptr, cap) };
        }
    }
}

/// A `T` on its own guard-paged, page-locked heap pages.
///
/// Compared to a plain `Box`, the value never shares a page with unrelated
/// data, its pages are `mlock`ed/`VirtualLock`ed (best effort) and excluded
/// from core dumps on Linux/FreeBSD, and dropping zeroizes the whole region
/// before returning it to the allocator.
///
/// `T: Copy` keeps this simple and sound: no destructor can run on the
/// zeroized bytes. Note that constructing (`new` takes `T` by value) and
/// copying the value out both leave transient stack copies outside the
/// locked pages — keep those short-lived.
pub struct LockedBox<T: Copy> {
    ptr: NonNull<T>,
    locked: bool,
}

impl<T: Copy> LockedBox<T> {
    pub fn new(value: T) -> Self {
        const {
            assert!(size_of::<T>() > 0, "LockedBox of a zero-sized type");
            // memsec places the value flush against the end of its pages;
            // any power-of-two alignment <= 4096 divides every real page
            // size, keeping that placement aligned for T.
            assert!(
                align_of::<T>() <= 4096,
                "LockedBox alignment exceeds page size"
            );
        }
        // SAFETY: size/alignment checked above; memsec returns writable
        // memory of at least size_of::<T>() bytes.
        let ptr: NonNull<T> = unsafe { memsec::malloc() }.expect("secure allocation failed");
        // SAFETY: fresh allocation owned by us, valid for writes of T.
        unsafe { ptr.as_ptr().write(value) };
        // memsec::malloc already mlocks but discards the result; probe again
        // so degraded environments surface the one-time warning and
        // `is_locked` reports the truth.
        // SAFETY: the allocation is live and owned until Drop.
        let locked = unsafe { lock_region(ptr.as_ptr() as *const u8, size_of::<T>()) };
        Self { ptr, locked }
    }

    /// Whether the pages are actually pinned (false in degraded
    /// environments; the value still lives on guarded, zeroize-on-drop
    /// pages either way).
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl<T: Copy> Deref for LockedBox<T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: `ptr` is valid and exclusively owned for `self`'s lifetime.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: Copy> Drop for LockedBox<T> {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from `memsec::malloc` and is dropped exactly
        // once. `free` zeroizes the region, unlocks it, and verifies the
        // canary before releasing the pages.
        unsafe { memsec::free(self.ptr) };
    }
}

impl<T: Copy> std::fmt::Debug for LockedBox<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockedBox(<redacted>)")
    }
}

// SAFETY: LockedBox owns its allocation exclusively, exactly like Box<T>.
unsafe impl<T: Copy + Send> Send for LockedBox<T> {}
unsafe impl<T: Copy + Sync> Sync for LockedBox<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_redacts_debug() {
        let lb = LockedBox::new([7u8; 32]);
        assert_eq!(*lb, [7u8; 32]);
        assert_eq!(format!("{lb:?}"), "LockedBox(<redacted>)");
    }

    #[test]
    fn drop_is_clean_and_boxes_are_independent() {
        let a = LockedBox::new([1u8; 32]);
        let b = LockedBox::new([2u8; 32]);
        drop(a); // must not abort (canary intact) nor disturb `b`
        assert_eq!(*b, [2u8; 32]);
    }

    #[test]
    fn zero_len_region_is_never_locked() {
        // SAFETY: len == 0 is an explicit no-op; the pointer is not used.
        assert!(!unsafe { lock_region(core::ptr::NonNull::<u8>::dangling().as_ptr(), 0) });
    }

    #[test]
    fn locked_string_round_trips_and_drops_clean() {
        let s = LockedString::new("hunter2".to_owned());
        assert_eq!(s.as_str(), "hunter2");
        drop(s);
        // Capacity-0 strings have no heap buffer to lock; must be a no-op.
        let empty = LockedString::new(String::new());
        assert_eq!(empty.as_str(), "");
        assert!(!empty.locked);
    }

    /// On Linux, a live LockedBox must show up in the process's locked-page
    /// accounting (skipped when the environment cannot mlock at all).
    #[cfg(target_os = "linux")]
    #[test]
    fn locked_pages_appear_in_vmlck() {
        let lb = LockedBox::new([3u8; 32]);
        if !lb.is_locked() {
            eprintln!("mlock unavailable here; skipping VmLck assertion");
            return;
        }
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let vmlck: u64 = status
            .lines()
            .find(|l| l.starts_with("VmLck:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|kb| kb.parse().ok())
            .expect("VmLck line in /proc/self/status");
        assert!(vmlck > 0, "expected VmLck > 0, got {vmlck} kB");
    }
}
