#[macro_use]
extern crate criterion;

use criterion::{Criterion, Bencher, black_box};

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
    Deployer, Sender, Watcher,
    EventDB, BlockNumDB,
    eth::*,
};
use anonify_runtime::U64;
use anonify_app_preluder::construct;

const ANONYMOUS_ASSET_ABI_PATH: &str = "../build/Anonify.abi";

#[derive(Clone, Debug)]
pub struct ERC20Bencher<'a, D, S, W, DB>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    my_roster_idx: &'a str,
    max_roster_idx: &'a str,
    state_id: u64,
    gas: u64,
    access_right: Option<AccessRight>,
    contract_addr: Option<String>,
    pub dispatcher: Option<Dispatcher<D, S, W, DB>>,
}

impl ERC20Bencher<D, S, W, DB>
    where
        D: Deployer,
        S: Sender,
        W: Watcher<WatcherDB=DB>,
        DB: BlockNumDB,
{
    pub fn with_param(
        my_roster_idx: &str,
        max_roster_idx: &str,
        state_id: u64,
        gas: u64,
    ) -> Self {
        Self {
            my_roster_idx,
            max_roster_idx,
            state_id,
            gas,
            access_right: None,
            contract_addr: None,
            dispatcher: None,
        }
    }

    pub fn setup_dispatcher(&mut self) {
        env::set_var("MY_ROSTER_IDX", self.my_roster_idx);
        env::set_var("MAX_ROSTER_IDX", self.max_roster_idx);
        let enclave = EnclaveDir::new().init_enclave(true).unwrap();
        let eid = enclave.geteid();
        let access_right = AccessRight::new_from_rng().unwrap();

        let event_db = Arc::new(EventDB::new());
        let mut dispatcher = Dispatcher::<EthDeployer, EthSender, EventWatcher<EventDB>, EventDB>::new(eid, ETH_URL, event_db).unwrap();

        let deployer_addr = dispatcher.get_account(0).unwrap();
        let contract_addr = dispatcher.deploy(&deployer_addr).unwrap();
        dispatcher.set_contract_addr(&contract_addr, ANONYMOUS_ASSET_ABI_PATH).unwrap();

        self.access_right = Some(access_right);
        self.contract_addr = Some(contract_addr);
        self.dispatcher = Some(dispatcher);
    }

    pub fn bench_construct(&self, b: &mut Bencher) {
        let total_supply = U64::from_raw(100);
        let init_state = construct { total_supply };

        b.iter(|| {
            let receipt = self.dispatcher.unwrap().state_transition(
                self.access_right.unwrap(),
                init_state,
                self.state_id,
                "construct",
                self.dispatcher.unwrap().get_account(0).unwrap(),
                self.gas,
                &(self.contract_addr.unwrap()),
                ANONYMOUS_ASSET_ABI_PATH,
            ).unwrap();
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
    bencher.setup_dispatcher();
    bencher.bench_construct(b);
}

fn erc20_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ERC20 Benchmark");
    group.bench_function("construct", |b| bench_construct(b));
}

criterion_group!(benches, erc20_benchmark);
criterion_main!(benches);