use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use super::failure::{Failure, TestResult};

/// A userspace consumer on nfqueue queues: it accepts every packet and counts them per queue.
pub struct QueueConsumer {
    stop: Arc<AtomicBool>,
    counts: Arc<BTreeMap<u16, AtomicU64>>,
    worker: Option<JoinHandle<TestResult>>,
}

impl QueueConsumer {
    pub fn start(queues: &[u16]) -> TestResult<Self> {
        let mut queue =
            nfq::Queue::open().map_err(|error| Failure::context("open nfqueue", error))?;
        for number in queues {
            queue
                .bind(*number)
                .map_err(|error| Failure::context(format!("bind nfqueue {number}"), error))?;
        }
        queue.set_nonblocking(true);

        let counts: Arc<BTreeMap<u16, AtomicU64>> = Arc::new(
            queues
                .iter()
                .map(|number| (*number, AtomicU64::new(0)))
                .collect(),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let worker = std::thread::spawn({
            let counts = Arc::clone(&counts);
            let stop = Arc::clone(&stop);
            move || -> TestResult {
                while !stop.load(Ordering::Acquire) {
                    match queue.recv() {
                        Ok(message) => {
                            if let Some(count) = counts.get(&message.get_queue_num()) {
                                count.fetch_add(1, Ordering::Relaxed);
                            }
                            // A received message's verdict defaults to accept.
                            queue.verdict(message).map_err(|error| {
                                Failure::context("issue nfqueue verdict", error)
                            })?;
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => return Err(Failure::context("receive from nfqueue", error)),
                    }
                }
                Ok(())
            }
        });
        Ok(Self {
            stop,
            counts,
            worker: Some(worker),
        })
    }

    pub fn count(&self, queue: u16) -> u64 {
        self.counts
            .get(&queue)
            .map_or(0, |count| count.load(Ordering::Relaxed))
    }

    /// Stop consuming and report any error the worker hit.
    pub fn stop(mut self) -> TestResult {
        self.stop.store(true, Ordering::Release);
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_panic| Failure::new("nfqueue worker panicked"))?,
            None => Ok(()),
        }
    }
}

impl Drop for QueueConsumer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}
