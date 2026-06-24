extern crate alloc;

pub mod sync {
    use std::sync::{Mutex, MutexGuard};

    pub struct SpinIrq<T> {
        inner: Mutex<T>,
    }

    impl<T> SpinIrq<T> {
        pub const fn new(value: T) -> Self {
            Self {
                inner: Mutex::new(value),
            }
        }

        pub fn lock(&self) -> MutexGuard<'_, T> {
            self.inner.lock().unwrap()
        }
    }

    // SAFETY: the host SpinIrq is a Send+Sync wrapper around
    // std::sync::Mutex, which is itself Send+Sync where T is Send.
    unsafe impl<T: Send> Send for SpinIrq<T> {}
    unsafe impl<T: Send> Sync for SpinIrq<T> {}
}

pub mod user {
    use alloc::vec::Vec;
    use std::collections::HashMap;
    use std::sync::RwLock;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UserAccessFault;

    pub struct TrapFrame {
        _private: (),
    }

    static REGISTRY: RwLock<Option<HashMap<u64, Vec<u8>>>> = RwLock::new(None);

    fn with_registry<R>(f: impl FnOnce(&mut HashMap<u64, Vec<u8>>) -> R) -> R {
        let mut guard = REGISTRY.write().unwrap();
        if guard.is_none() {
            *guard = Some(HashMap::new());
        }
        f(guard.as_mut().unwrap())
    }

    pub fn register_user_buffer(addr: u64, buf: Vec<u8>) {
        with_registry(|r| {
            r.insert(addr, buf);
        });
    }

    pub fn take_user_buffer(addr: u64) -> Option<Vec<u8>> {
        with_registry(|r| r.remove(&addr))
    }

    pub fn copy_from_user(addr: u64, dst: &mut [u8]) -> Result<(), UserAccessFault> {
        with_registry(|r| {
            let src = r.get(&addr).ok_or(UserAccessFault)?;
            if src.len() < dst.len() {
                return Err(UserAccessFault);
            }
            dst.copy_from_slice(&src[..dst.len()]);
            Ok(())
        })
    }

    pub fn copy_to_user(addr: u64, src: &[u8]) -> Result<(), UserAccessFault> {
        with_registry(|r| {
            let dst = r.get_mut(&addr).ok_or(UserAccessFault)?;
            if dst.len() < src.len() {
                return Err(UserAccessFault);
            }
            dst[..src.len()].copy_from_slice(src);
            Ok(())
        })
    }

    pub fn cmpxchg_user_u32(addr: u64, expected: u32, new: u32) -> Result<u32, UserAccessFault> {
        with_registry(|r| {
            let buf = r.get_mut(&addr).ok_or(UserAccessFault)?;
            if buf.len() < 4 {
                return Err(UserAccessFault);
            }
            let prev = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            if prev == expected {
                buf[..4].copy_from_slice(&new.to_le_bytes());
            }
            Ok(prev)
        })
    }
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        std::println!($($arg)*);
    }};
}

pub mod cpu {
    pub mod per_cpu {
        pub const MAX_CPUS: usize = 1;
        pub fn current_cpu_id() -> usize {
            0
        }
    }
    pub mod task {
        pub struct Task;
        pub struct Context;
    }
    pub mod clock {
        use std::sync::OnceLock;
        use std::time::Instant;
        pub fn nanos_since_boot() -> u64 {
            static START: OnceLock<Instant> = OnceLock::new();
            START.get_or_init(Instant::now).elapsed().as_nanos() as u64
        }
    }
}

pub mod mm {
    pub struct VirtAddr(pub u64);
    pub struct PhysFrame;
    pub struct Page;
    pub struct Size4KiB;
    pub mod vm {
        pub struct Perms;
        pub struct VmSpace;
        pub enum MapError {
            #[allow(dead_code)]
            Unimplemented,
        }
    }
    pub fn frame_alloc() -> Option<PhysFrame> {
        None
    }
    pub fn write_to_frame(_frame: &PhysFrame, _offset: usize, _data: &[u8]) {}
    pub fn read_from_frame(_frame: &PhysFrame, _offset: usize, _dst: &mut [u8]) {}
    pub fn zero_frame(_frame: &PhysFrame) {}
}

pub mod io {
    pub mod qemu_exit {
        pub enum ExitCode {
            Success,
            Failure,
        }
        pub fn exit(_code: ExitCode) -> ! {
            std::process::exit(0)
        }
    }
}
