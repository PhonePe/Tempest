// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::Mutex;

/// Independent hard bound on live source identities; never evict a live permit.
pub(super) const MAX_TFTP_CLIENT_IDENTITIES: usize = 100_000;

/// Shared by every listener shard; counts queued, reserved and running TFTP work.
#[derive(Debug)]
pub(crate) struct TftpClientLimits {
    limit: usize,
    counts: Mutex<HashMap<IpAddr, usize>>,
}

impl TftpClientLimits {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            counts: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<TftpClientPermit> {
        let ip = match ip {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            ip => ip,
        };
        let mut counts = self.counts.lock();
        if let Some(count) = counts.get_mut(&ip) {
            if *count >= self.limit {
                return None;
            }
            *count += 1;
        } else {
            if self.limit == 0 || counts.len() >= MAX_TFTP_CLIENT_IDENTITIES {
                return None;
            }
            counts.insert(ip, 1);
        }
        Some(TftpClientPermit {
            limits: self.clone(),
            ip,
        })
    }

    #[cfg(test)]
    pub(super) fn identities(&self) -> usize {
        self.counts.lock().len()
    }
}

/// Non-cloneable ownership follows the client TID through every admission stage.
#[derive(Debug)]
pub(super) struct TftpClientPermit {
    limits: Arc<TftpClientLimits>,
    ip: IpAddr,
}

impl Drop for TftpClientPermit {
    fn drop(&mut self) {
        let mut counts = self.limits.counts.lock();
        let count = counts.get_mut(&self.ip).expect("live TFTP client permit");
        *count -= 1;
        if *count == 0 {
            counts.remove(&self.ip);
        }
    }
}
