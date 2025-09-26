use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::sync::RwLock;

lazy_static! {
    /// Global registry for compiled regexes to avoid recompilation
    /// TODO: HashMap keys allocate memory - consider using &'static str keys or pre-compiled cache
    static ref REGEX_CACHE: RwLock<HashMap<String, Result<Regex, String>>> =
        RwLock::new(HashMap::new());
}
