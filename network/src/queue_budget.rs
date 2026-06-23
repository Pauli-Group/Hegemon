use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Debug)]
pub(crate) struct ByteBudget {
    used: Arc<AtomicUsize>,
    max: usize,
}

#[derive(Debug)]
pub(crate) struct BytePermit {
    budget: ByteBudget,
    bytes: usize,
}

impl ByteBudget {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            used: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    pub(crate) fn try_acquire(&self, bytes: usize) -> Option<BytePermit> {
        let bytes = bytes.max(1);
        let mut current = self.used.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(bytes)?;
            if next > self.max {
                return None;
            }
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(BytePermit {
                        budget: self.clone(),
                        bytes,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for BytePermit {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
