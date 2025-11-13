#[macro_export]
macro_rules! register_windows_actions {
    ($runner:expr, $( $sim:ty ),* $(,)?) => {
        $(
            $runner.register(Box::new(<$sim>::default()));
        )*
    };
}
