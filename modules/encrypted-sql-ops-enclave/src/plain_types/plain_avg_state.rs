use crate::aggregate_calc::AggregateCalc;
use crate::error::Result;
use crate::type_crypt::{Pad16BytesDecrypt, Pad16BytesEncrypt};
use module_encrypted_sql_ops_ecall_types::enc_type::enc_aggregate_state::EncAvgState;

use super::PlainInteger;

/// Intermediate state to calculate average.
///
/// FIXME: Currently `i32` input and `f32` output is only supported.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct PlainAvgState {
    /// current total
    pub sum: PlainInteger,

    /// current number of values
    pub n: PlainInteger,
}

impl PlainAvgState {
    /// Constructor from EncAvgState
    pub fn from_encrypted(encrypted: EncAvgState) -> Result<Self> {
        match encrypted {
            EncAvgState::Interm { sum, n } => {
                let plain_sum = sum.decrypt()?;
                let plain_n = n.decrypt()?;
                Ok(Self {
                    sum: plain_sum,
                    n: plain_n,
                })
            }
            EncAvgState::Initial => Ok(Self::default()),
        }
    }

    /// Encrypt to EncAvgState
    pub fn to_encrypted(self) -> EncAvgState {
        let enc_sum = self.sum.encrypt();
        let enc_n = self.n.encrypt();
        EncAvgState::Interm {
            sum: enc_sum,
            n: enc_n,
        }
    }
}

impl AggregateCalc for PlainAvgState {
    fn accumulate(&mut self, val: i32) {
        self.sum = PlainInteger::new(self.sum.to_i32() + val);
        self.n = PlainInteger::new(self.n.to_i32() + 1);
    }

    fn finalize(self) -> f32 {
        (self.sum.to_i32() as f32) / (self.n.to_i32() as f32)
    }
}

#[cfg(test)]
mod tests {
    use crate::{aggregate_calc::AggregateCalc, plain_types::PlainAvgState};

    #[test]
    fn test_no_sample() {
        let avg_state = PlainAvgState::default();
        assert!(avg_state.finalize().is_nan());
    }

    #[test]
    fn test_calculation() {
        let mut avg_state = PlainAvgState::default();
        avg_state.accumulate(1);
        avg_state.accumulate(2);
        assert_eq!(avg_state.finalize(), 1.5);
    }
}
