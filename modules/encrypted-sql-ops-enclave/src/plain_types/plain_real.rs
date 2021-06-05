/// Plain representation of REAL (32-bit float).
#[derive(Clone, PartialEq, Debug, Default)]
pub struct PlainReal(f32);

impl PlainReal {
    /// Constructor
    pub fn new(f: f32) -> Self {
        Self(f)
    }

    /// Get raw representation
    pub fn to_f32(&self) -> f32 {
        self.0
    }
}
