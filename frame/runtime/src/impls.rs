#[macro_export]
macro_rules! impl_memory {
    ( $( $t:tt )* ) => {
        $crate::__impl_inner_memory!(@normalize $( $t )* );
    };
}

#[macro_export]
macro_rules! __impl_inner_memory {
    (@normalize
        $( ($id:expr, $name:expr, Address => $value:ty) ),*
    ) => {
        $crate::__impl_inner_memory!(@normalize $( ($id, $name, $value) ),* );
    };

    (@normalize
        $( ($id:expr, $name:expr, $value:ty) ),*
    ) => {
        $crate::__impl_inner_memory!(@imp $( ($id, $name, $value) ),* );
    };

    (@imp
        $( ($id:expr, $name:expr, $value:ty) ),*
    ) => {
        #[derive(Debug, Clone)]
        pub struct MemName;

        impl MemNameConverter for MemName {
            fn as_id(name: &str) -> MemId {
                match name {
                    $( $name => MemId::from_raw($id), )*
                    _ => panic!("invalid mem name"),
                }
            }
        }

        /// Return maximum size of mem values
        fn max_size() -> usize {
            *[ $( <$value>::default().size(), )* ]
                .iter()
                .max()
                .expect("Iterator should not be empty.")
        }
    };
}

#[macro_export]
macro_rules! impl_runtime {
    (
        $( $t:tt )*
    ) => {
        $crate::__impl_inner_runtime!(@imp
            $($t)*
        );
    };
}

#[macro_export]
macro_rules! __impl_inner_runtime {
    (@imp
        $(
            pub fn $fn_name:ident(
                $runtime:ident,
                $sender:ident : $account_id:ty
                $(, $param_name:ident : $param:ty )*
            ) {
                $( $impl:tt )*
            }
        )*
    ) => {
        $(
            #[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone, Default)]
            #[serde(crate = "crate::serde")]
            #[allow(non_camel_case_types)]
            pub struct $fn_name {
                $( pub $param_name: $param, )*
            }

        )*

        #[cfg(feature = "sgx")]
        #[derive(Debug, Clone, Encode, Decode)]
        pub enum CallKind {
            $(
                #[allow(non_camel_case_types)]
                $fn_name($fn_name),
            )*
        }

        #[cfg(feature = "sgx")]
        impl<G> CallKindExecutor<G> for CallKind
        where
            G: ContextOps<S=StateType>,
        {
            type R = Runtime<G>;
            type S = StateType;

            fn new(cmd_name: &str, cmd: serde_json::Value) -> Result<Self> {
                match cmd_name {
                    $( stringify!($fn_name) => {
                        if cmd.is_null() {
                            Ok(CallKind::$fn_name($fn_name::default()))
                        } else {
                            Ok(CallKind::$fn_name(serde_json::from_value(cmd)?))
                        }
                    },)*
                    _ => return Err(anyhow!("Invalid Command Name")),
                }
            }

            fn execute(self, runtime: Self::R, my_account_id: AccountId) -> Result<ReturnState<Self::S>> {
                match self {
                    $( CallKind::$fn_name($fn_name) => {
                        runtime.$fn_name(
                            my_account_id,
                            $( $fn_name.$param_name, )*
                        )
                    }, )*
                    _ => unimplemented!()
                }
            }
        }

        #[cfg(feature = "sgx")]
        pub struct Runtime<G: ContextOps<S=StateType>> {
            db: G,
        }

        #[cfg(feature = "sgx")]
        impl<G> RuntimeExecutor<G> for Runtime<G>
        where
            G: ContextOps<S=StateType>,
        {
            type C = CallKind;
            type S = StateType;

            fn new(db: G) -> Self {
                Runtime {
                    db,
                }
            }

            fn execute(self, kind: Self::C, my_account_id: AccountId) -> Result<ReturnState<Self::S>> {
                kind.execute(self, my_account_id)
            }
        }

        #[cfg(feature = "sgx")]
        impl<G> Runtime<G>
        where
            G: ContextOps<S=StateType>,
        {
            pub fn get_map<S: State>(
                &self,
                key: AccountId,
                name: &str
            ) -> Result<S> {
                let mem_id = MemName::as_id(name);
                let mut tmp = self.db.get_state_by_mem_id(key, mem_id).into_vec();
                if tmp.is_empty() {
                    Ok(S::default())
                } else {
                    S::decode_s(&mut tmp)
                }
            }

            pub fn values<S: State>(mut self) -> Result<Vec<S>> {
                self.db.values().into_iter().map(|e| S::decode_s(&mut e.into_vec())).collect()
            }

            $(
                pub fn $fn_name (
                    $runtime,
                    $sender: $account_id
                    $(, $param_name : $param )*
                ) -> Result<ReturnState<StateType>> {
                    $( $impl )*
                }
            )*
        }
    };
}

#[macro_export]
macro_rules! update {
    ($account_id:expr, $mem_name:expr, $value:expr) => {
        UpdatedState::new($account_id, MemName::as_id($mem_name), $value)?
    };

    ($mem_name:expr, $value:expr) => {
        UpdatedState::new($mem_name, MemName::as_id($mem_name), $value)?
    };
}

#[macro_export]
macro_rules! return_update {
    ( $($update:expr),* ) => {
        Ok(ReturnState::Updated(vec![$( $update),* ]))
    };
}

#[macro_export]
macro_rules! get_state {
    ( $state:expr ) => {
        Ok(ReturnState::Get($state.into()))
    };
}
