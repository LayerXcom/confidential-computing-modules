// use crate::localstd::{collections::HashMap, time::SystemTime};
// use once_cell::sync::Lazy;
// use parking_lot::Mutex;

// static PENDING_TX: Lazy<Mutex<HashMap<i32, SystemTime>>> = Lazy::new(|| {
//     let mut m = HashMap::new();
//     m.insert(0, SystemTime::now());
//     Mutex::new(m)
// });