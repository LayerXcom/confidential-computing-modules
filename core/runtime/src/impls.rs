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
        pub struct MemName<'a>(&'a str);

        impl MemNameConverter for MemName<'_> {
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
                .into_iter()
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
            #[fn_id=$fn_id:expr]
            pub fn $fn_name:ident(
                $runtime:ident,
                $sender:ident : $address:ty
                $(, $param_name:ident : $param:ty )*
            ) {
                $( $impl:tt )*
            }
        )*
    ) => {
        $(
            #[derive(Encode, Decode, Debug, Clone, Default)]
            pub struct $fn_name {
                $( pub $param_name: $param, )*
            }
        )*

        #[derive(Debug, Clone, Encode, Decode)]
        pub enum CallKind {
            $( $fn_name($fn_name), )*
        }

        impl<G: StateGetter> CallKindConverter<G> for CallKind {
            type S = Runtime<G>;

            fn from_call_id(id: u32, state: &mut [u8]) -> Result<Self> {
                match id {
                    $( $fn_id => Ok(CallKind::$fn_name($fn_name::from_bytes(state)?)), )*
                    _ => return Err(anyhow!("Invalid Call ID")),
                }
            }

            fn find_stf(self, runtime: Self::S, my_addr: UserAddress) -> Result<Vec<UpdatedState<StateType>>> {
                match self {
                    $( CallKind::$fn_name($fn_name) => {
                        runtime.$fn_name(
                            my_addr,
                            $( $fn_name.$param_name, )*
                        )
                    }, )*
                    _ => unimplemented!()
                }
            }
        }

        pub fn call_name_to_id(name: &str) -> u32 {
            match name {
                $( stringify!($fn_name) => $fn_id, )*
                _ => panic!("invalid call name"),
            }
        }

        pub struct Runtime<G: StateGetter> {
            db: G,
        }

        impl<G: StateGetter> StateTransition<G> for Runtime<G> {
            type C = CallKind;

            fn new(db: G) -> Self {
                Runtime {
                    db,
                }
            }

            fn call(self, kind: Self::C, my_addr: UserAddress) -> Result<Vec<UpdatedState<StateType>>>
            where
                // C: CallKindConverter<G>,
                // // Runtime<G>: <C as CallKindConverter<G>>::S,
                // <C as CallKindConverter<G>>::S: StateTransition<G>,
            {
                kind.find_stf(self, my_addr)
            }
        }

        impl<G: StateGetter> Runtime<G> {
            pub fn get_map<S: State>(
                &self,
                key: UserAddress,
                name: &str
            ) -> Result<S> {
                let mem_id = MemName::as_id(name);
                self.db.get(key, mem_id)
            }

            pub fn get<S: State>(&self, name: &str) -> Result<S> {
                let mem_id = MemName::as_id(name);
                self.db.get(name, mem_id)
            }

            $(
                pub fn $fn_name (
                    $runtime,
                    $sender: $address
                    $(, $param_name : $param )*
                ) -> Result<Vec<UpdatedState<StateType>>> {
                    $( $impl )*
                }
            )*
        }
    };
}

#[macro_export]
macro_rules! update {
    ($addr:expr, $mem_name:expr, $value:expr) => {
        UpdatedState::new($addr, MemName::as_id($mem_name), $value)
    };

    ($mem_name:expr, $value:expr) => {
        UpdatedState::new($mem_name, MemName::as_id($mem_name), $value)
    };
}

#[macro_export]
macro_rules! insert {
    ( $($update:expr),* ) => {
        Ok(vec![$( $update),* ])
    };
}
