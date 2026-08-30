use std::hash::{Hash, Hasher};

use super::*;
impl PolicySnapshot {
    pub(super) fn match_cidr(&self, ip: IpAddr) -> Option<CidrPolicyMatch<'_>> {
        match ip {
            IpAddr::V4(_) => self
                .cidr_rules_v4
                .iter()
                .find(|rule| rule.cidr.contains(ip)),
            IpAddr::V6(_) => self
                .cidr_rules_v6
                .iter()
                .find(|rule| rule.cidr.contains(ip)),
        }
        .map(CidrPolicyMatch::Explicit)
        .or_else(|| self.match_auto_cidr(ip))
    }

    pub(super) fn match_auto_cidr(&self, ip: IpAddr) -> Option<CidrPolicyMatch<'_>> {
        let rule = match ip {
            IpAddr::V4(_) => self.cidr_auto_rules_v4.first()?,
            IpAddr::V6(_) => self.cidr_auto_rules_v6.first()?,
        };
        let key = auto_cidr_bucket_key(ip, rule.prefix_len)?;
        Some(CidrPolicyMatch::Auto {
            key,
            limits: rule.limits,
        })
    }
}

impl<T> ShardedRegistry<T> {
    pub(super) fn new(shards: usize) -> Self {
        let shard_count = shards.max(1).next_power_of_two();
        let mut items = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            items.push(DashMap::<String, Arc<T>>::new());
        }
        Self {
            shards: items.into_boxed_slice(),
            mask: shard_count.saturating_sub(1),
        }
    }

    pub(super) fn shard_index(&self, key: &str) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & self.mask
    }

    pub(super) fn get_or_insert_with<F, A>(&self, key: &str, make: F, activate: A) -> Arc<T>
    where
        F: FnOnce() -> T,
        A: FnOnce(&Arc<T>),
    {
        let shard = &self.shards[self.shard_index(key)];
        match shard.entry(key.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(entry) => {
                activate(entry.get());
                Arc::clone(entry.get())
            }
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                let value = Arc::new(make());
                activate(&value);
                slot.insert(Arc::clone(&value));
                value
            }
        }
    }

    pub(super) fn retain<F>(&self, predicate: F)
    where
        F: Fn(&String, &Arc<T>) -> bool + Copy,
    {
        for shard in &*self.shards {
            shard.retain(|key, value| predicate(key, value));
        }
    }

    pub(super) fn remove_if<F>(&self, key: &str, predicate: F) -> bool
    where
        F: Fn(&Arc<T>) -> bool,
    {
        let shard = &self.shards[self.shard_index(key)];
        shard.remove_if(key, |_, value| predicate(value)).is_some()
    }
}
