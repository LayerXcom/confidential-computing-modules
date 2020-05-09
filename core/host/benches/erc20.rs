#[macro_use]
extern crate criterion;

use criterion::{Criterion, Bencher};

use anonify_host::{
    EnclaveDir,
    Dispatcher,
};
use anonify_common::AccessRight;
use std::{
    sync::Arc,
    env,
};
use anonify_event_watcher::{
    EventDB, BlockNumDB,
    eth::*,
};
use anonify_runtime::U64;
use anonify_app_preluder::construct;
use anyhow::Result;

const ETH_URL: &'static str = "http://172.18.0.2:8545";
const ANONYMOUS_ASSET_ABI_PATH: &str = "../../build/Anonify.abi";

#[derive(Debug, Clone)]
pub struct ERC20Bencher {
    my_roster_idx: &'static str,
    max_roster_idx: &'static str,
    state_id: u64,
    gas: u64,
    access_right: AccessRight,
    contract_addr: Option<String>,
}

impl ERC20Bencher {
    pub fn with_param(
        my_roster_idx: &'static str,
        max_roster_idx: &'static str,
        state_id: u64,
        gas: u64,
    ) -> Self {
        let access_right = AccessRight::new_from_rng().unwrap();
        Self {
            my_roster_idx,
            max_roster_idx,
            state_id,
            gas,
            access_right,
            contract_addr: None,
        }
    }

    pub fn setup_dispatcher(&mut self) -> Result<Dispatcher<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>> {
        env::set_var("MY_ROSTER_IDX", self.my_roster_idx);
        env::set_var("MAX_ROSTER_IDX", self.max_roster_idx);
        let enclave = EnclaveDir::new().init_enclave(true)?;
        let eid = enclave.geteid();

        let event_db = Arc::new(EventDB::new());
        let dispatcher = Dispatcher::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid, ETH_URL, event_db)?;

        let deployer_addr = dispatcher.get_account(0)?;
        let contract_addr = dispatcher.deploy(&deployer_addr)?;
        dispatcher.set_contract_addr(&contract_addr, ANONYMOUS_ASSET_ABI_PATH)?;

        self.contract_addr = Some(contract_addr);
        Ok(dispatcher)
    }

    pub fn bench_construct(&self, b: &mut Bencher, dispatcher: &Dispatcher<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>) {
        let total_supply = U64::from_raw(100);
        let init_state = construct { total_supply };

        b.iter(|| {
            dispatcher.state_transition(
                self.access_right.clone(),
                init_state.clone(),
                self.state_id.clone(),
                "construct",
                dispatcher.get_account(0).unwrap(),
                self.gas.clone(),
                self.contract_addr.as_ref().unwrap().as_str(),
                ANONYMOUS_ASSET_ABI_PATH,
            );
        })
    }
}

pub fn bench_construct(b: &mut Bencher) {
    let mut bencher = ERC20Bencher::with_param(
        "0",
        "2",
        0,
        3_000_000,
    );
    let dispatcher = bencher.setup_dispatcher().unwrap();
    bencher.bench_construct(b, &dispatcher);
}

fn erc20_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ERC20 Benchmark");
    group.bench_function("construct", |b| bench_construct(b));
}

criterion_group!(benches, erc20_benchmark);
criterion_main!(benches);