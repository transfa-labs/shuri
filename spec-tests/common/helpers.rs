macro_rules! assert_post_state {
    ($expected:expr, $actual:expr) => {
        if let Some(expected) = $expected {
            similar_asserts::assert_eq!(expected, $actual);
        }
    };
}
