//! Secure locked memory buffers preventing swap/paging leaks via mlock and ZeroizeOnDrop.

use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A memory buffer locked in RAM (`mlock`) that zeroizes memory on drop
pub struct LockedBuffer<T: Zeroize> {
    data: T,
    locked: bool,
}

impl<T: Zeroize> LockedBuffer<T> {
    pub fn new(data: T) -> Self {
        let mut buffer = Self {
            data,
            locked: false,
        };
        buffer.lock();
        buffer
    }

    fn lock(&mut self) {
        let ptr = &self.data as *const T as *const libc::c_void;
        let size = std::mem::size_of::<T>();
        unsafe {
            if libc::mlock(ptr, size) == 0 {
                self.locked = true;
            }
        }
    }

    fn unlock(&mut self) {
        if self.locked {
            let ptr = &self.data as *const T as *const libc::c_void;
            let size = std::mem::size_of::<T>();
            unsafe {
                libc::munlock(ptr, size);
            }
            self.locked = false;
        }
    }
}

impl<T: Zeroize> Deref for LockedBuffer<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: Zeroize> DerefMut for LockedBuffer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: Zeroize> Drop for LockedBuffer<T> {
    fn drop(&mut self) {
        self.data.zeroize();
        self.unlock();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for LockedBuffer<T> {}
