#[macro_export]
macro_rules! define_typed_size {
    ($name:ident, $target_type:ty, $source:ty) => {
        const $name: $target_type = const {
            let size = core::mem::size_of::<$source>();

            if size > <$target_type>::MAX as usize {
                panic!(concat!(
                    "The size of `",
                    stringify!($source),
                    "` exceeds the capacity of type `",
                    stringify!($target_type),
                    "`"
                ));
            }

            #[expect(
                clippy::cast_possible_truncation,
                reason = "We validate that the size fits in the target size"
            )]
            {
                size as $target_type
            }
        };
    };
}
