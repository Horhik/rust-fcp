mod types;
pub use types::client;
pub use types::node;

#[cfg(test)]
mod tests {

    #[macro_export]
    macro_rules! vec {
    ( $( $x:expr ),* ) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push($x);
            )*
            temp_vec
        }
    };
}

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
