use anonify_treekem::{
    GroupState, AppKeyChain, Handshake,
    handshake::{PathSecretRequest, HandshakeParams},
};
use anyhow::Result;

#[derive(Clone, Debug)]
pub struct GroupKey {
    group_state: GroupState,
    keychain: AppKeyChain,
    max_roster_idx: usize,
    path_secret_req: PathSecretRequest,
}

impl GroupKey {
    pub fn new(
        my_roster_idx: usize,
        max_roster_idx: usize,
        path_secret_req: PathSecretRequest,
    ) -> Result<Self> {
        let group_state = GroupState::new(my_roster_idx)?;
        let keychain = AppKeyChain::default();

        Ok(GroupKey {
            group_state,
            keychain,
            max_roster_idx,
            path_secret_req,
        })
    }

    pub fn create_handshake(&self) -> Result<HandshakeParams> {
        self.group_state.create_handshake(self.path_secret_req)
    }

    pub fn process_handshake(&mut self, handshake: &HandshakeParams) -> Result<()> {
        let keychain = self.process_handshake(handshake, self.max_roster_idx)?;
        self.keychain = keychain;

        Ok(())
    }

    
}
