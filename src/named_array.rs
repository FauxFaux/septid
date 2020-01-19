#[macro_export]
macro_rules! named_array {
    ($name:ident, $len:expr) => {
        #[derive(Clone)]
        pub struct $name([u8; $len / 8]);

        #[allow(dead_code)]
        impl $name {
            pub const BYTES: usize = $len / 8;
            pub const BITS: usize = $len;

            pub fn random() -> Self {
                use rand::Rng as _;
                let mut ret = [0u8; Self::BYTES];
                rand::thread_rng().fill(&mut ret);
                Self(ret)
            }

            pub fn from_slice(data: &[u8]) -> Self {
                let mut ret = [0u8; Self::BYTES];
                ret.copy_from_slice(data);
                Self(ret)
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                (&mut self.0[..]).zeroize()
            }
        }
    };
}
