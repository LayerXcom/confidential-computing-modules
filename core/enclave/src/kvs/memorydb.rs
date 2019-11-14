use std::{
    sync::SgxRwLock as RwLock,
    collections::BTreeMap,
};
use anonify_common::types::*;

pub struct MemoryKVS(RwLock<BTreeMap<Address, Value>>);

