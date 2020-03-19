use crate::group_state::GroupState;
use crate::application::AppKeyChain;
use crate::crypto::{
    CryptoRng,
    secrets::PathSecret,
};

pub fn random_group_state() -> GroupState {
    let my_roster_idx = 0;

    GroupState::new(my_roster_idx).unwrap()
}

pub fn change_group_state_idx(
    group_state: &GroupState,
    new_idx: u32,
) -> GroupState {
    assert!(new_idx as usize <= group_state.roster_len().unwrap());

    let mut new_group_state = group_state.clone();
    new_group_state.my_roster_idx = new_idx;

    new_group_state
}

fn do_update_op<R: CryptoRng>(
    group1: &mut GroupState,
    group2: &mut GroupState,
    csprng: &mut R,
) -> (AppKeyChain, AppKeyChain) {
    let new_path_secret = PathSecret::new_from_random(csprng);
    unimplemented!();
}
