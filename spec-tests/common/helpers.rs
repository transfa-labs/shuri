macro_rules! assert_post_state {
    ($expected:expr, $actual:expr) => {
        if let Some(expected) = $expected {
            assert_eq!(expected, $actual);
        }
    };
}
