/// Wait for user input before panic!king.
#[macro_export]
macro_rules! panic_gracefully {
    () => ({ $crate::panic_gracefully!("explicit panic") });
    ($msg:expr $(,)?) => ({
        eprintln!($msg);
        std::io::stdin().read_line(&mut String::new()).unwrap();
        panic!($msg);
    });
    ($fmt:expr, $($arg:tt)+) => ({
        eprintln!($fmt, $($arg)+);
        std::io::stdin().read_line(&mut String::new()).unwrap();
        panic!($fmt, $($arg)+);
    });
}
