use crate::group_state::{GroupState, Handshake};
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

pub fn do_update_operation<R: CryptoRng>(
    group1: &mut GroupState,
    group2: &mut GroupState,
    csprng: &mut R,
) -> (AppKeyChain, AppKeyChain) {
    let new_path_secret = PathSecret::new_from_random(csprng);
    let (handshake, new_group1, keychain1) =  group1.create_update_handshake().unwrap();
    *group1 = new_group1;

    let (new_group2, keychain2) = group2.process_handshake(&handshake).unwrap();
    *group2 = new_group2;

    (keychain1, keychain2.unwrap())
}
