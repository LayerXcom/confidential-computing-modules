use crate::localstd::{
    path::Path,
    vec::Vec,
    fs,
    env,
};
use crate::local_anyhow::Result;
use crate::local_toml::Value;

lazy_static! {
    pub static ref CONFIG: Value = {
        let toml_path = env::var("TOML_PATH").unwrap_or("config.toml".to_string());
        read_toml(toml_path).unwrap()
    };
}

fn read_toml<T: AsRef<Path>>(path: T) -> Result<Value> {
    let toml_str = fs::read_to_string(path.as_ref())?;
    Value::try_from(toml_str).map_err(Into::into)
}
