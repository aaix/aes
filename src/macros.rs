#[macro_export]
macro_rules! printblock {
    ($name:expr, $val:expr) => {
        println!("{} is {:0>32x?}", $name, $val.display());
    };
}