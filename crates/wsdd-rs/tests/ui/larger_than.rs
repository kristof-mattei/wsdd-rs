use wsdd_rs::define_typed_size;

struct LargerThanU8 {
    _unused: [u8; 256],
}

define_typed_size!(SIZE_OF_LARGER_THAN_U8, u8, LargerThanU8);

fn main() {
    println!("{}", std::mem::size_of::<LargerThanU8>());
}
