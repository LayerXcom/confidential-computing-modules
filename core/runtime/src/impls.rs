#[macro_export]
macro_rules! impl_mem {
    ( $($id:expr, $name:expr, Address => $value:ty);* ;) => {
        pub fn mem_name_to_id(name: &str) -> MemId {
            match name {
                $( $name => MemId::from_raw($id) ),* ,
                _ => panic!("invalid mem name"),
            }
        }

        /// Return maximum size of mem values
        fn max_size() -> usize {
            *[$( <$value>::size(), )*]
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
        impl_inner_runtime!(@imp
            $($t)*
        );
    };
}

#[macro_export]
macro_rules! impl_inner_runtime {
    (@imp
        $(
            #[fn_id=$fn_id:expr]
            pub fn $fn_name:ident(
                $runtime:ident,
                $sender:ident : $address:ty
                $(, $param_name:ident : $param:ty )*
            ) -> Result<Vec<UpdatedState<StateType>>> {
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

        #[derive(Debug)]
        pub enum CallKind {
            $( $fn_name($fn_name), )*
        }

        impl CallKind {
            pub fn from_call_id(id: u32, state: &mut [u8]) -> Result<Self> {
                match id {
                    $( $fn_id => Ok(CallKind::$fn_name($fn_name::from_bytes(state)?)), )*
                    _ => return Err(anyhow!("Invalid Call ID")),
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

        impl<G: StateGetter> Runtime<G> {
            pub fn new(db: G) -> Self {
                Runtime {
                    db,
                }
            }

            pub fn call(
                self,
                kind: CallKind,
                my_addr: UserAddress,
            ) -> Result<Vec<UpdatedState<StateType>>> {
                match kind {
                    $( CallKind::$fn_name($fn_name) => {
                        self.$fn_name(
                            my_addr,
                            $( $fn_name.$param_name, )*
                        )
                    }, )*
                    _ => unimplemented!()
                }
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
        UpdatedState::new($addr, mem_name_to_id($mem_name), $value.into())
    };
}
