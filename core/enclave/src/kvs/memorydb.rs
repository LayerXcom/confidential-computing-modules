use std::{
    sync::SgxRwLock as RwLock,
    collections::BTreeMap,
};
use anonify_common::types::*;
use super::*;

pub struct MemoryKVS(RwLock<BTreeMap<Address, DBValue>>);

