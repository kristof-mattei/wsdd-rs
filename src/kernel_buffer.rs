use std::mem::{MaybeUninit, size_of};

mod private {
    pub(super) trait Private {}
}

#[expect(
    private_bounds,
    reason = "Arbitrary implementations don't make sense and are not supported"
)]
pub trait MapConstToType: private::Private {
    type Output;
}

#[expect(
    private_bounds,
    reason = "Arbitrary implementations don't make sense and are not supported"
)]
pub struct AlignedBuffer<const A: usize, const N: usize>
where
    ConstToType<A>: MapConstToType,
{
    buffer: Box<[MaybeUninit<<ConstToType<A> as MapConstToType>::Output>]>,
}

struct ConstToType<const U: usize>;

impl private::Private for ConstToType<1> {}
impl MapConstToType for ConstToType<1> {
    type Output = u8;
}

impl private::Private for ConstToType<2> {}
impl MapConstToType for ConstToType<2> {
    type Output = u16;
}

impl private::Private for ConstToType<4> {}
impl MapConstToType for ConstToType<4> {
    type Output = u32;
}

impl private::Private for ConstToType<8> {}
impl MapConstToType for ConstToType<8> {
    type Output = u64;
}

impl private::Private for ConstToType<16> {}
impl MapConstToType for ConstToType<16> {
    type Output = u128;
}

#[expect(
    private_bounds,
    reason = "Arbitrary implementations don't make sense and are not supported"
)]
impl<const A: usize, const N: usize> AlignedBuffer<A, N>
where
    ConstToType<A>: MapConstToType,
{
    const MAPPED_TYPE_SIZE: usize = size_of::<<ConstToType<A> as MapConstToType>::Output>();

    pub fn new() -> Self {
        // TODO move this to generics once we have support doing this kind of validation in const generics
        assert!(
            N.is_multiple_of(size_of::<<ConstToType<A> as MapConstToType>::Output>()),
            "N must be a multiple of the alignment size"
        );

        let len = N / Self::MAPPED_TYPE_SIZE;

        Self {
            buffer: Box::new_uninit_slice(len),
        }
    }
}

impl<const A: usize, const N: usize> AsRef<[MaybeUninit<u8>]> for AlignedBuffer<A, N>
where
    ConstToType<A>: MapConstToType,
{
    fn as_ref(&self) -> &[MaybeUninit<u8>] {
        // SAFETY:
        // - `u32` can be transmuted to `[u8; 4]`
        // - `MaybeUninit<T>` has the same layout as `T`
        // - `MaybeUninit<u32>` has the same memory layout as `[MaybeUninit<u8>; 4]`
        // - The buffer is a `Box<[MaybeUninit<u32>]>` of length N / 4, so it is valid for N bytes.
        unsafe { std::slice::from_raw_parts(self.buffer.as_ptr().cast::<MaybeUninit<u8>>(), N) }
    }
}

impl<const A: usize, const N: usize> AsMut<[MaybeUninit<u8>]> for AlignedBuffer<A, N>
where
    ConstToType<A>: MapConstToType,
{
    fn as_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        // SAFETY:
        // - `u32` can be transmuted to `[u8; 4]`
        // - `MaybeUninit<T>` has the same layout as `T`
        // - `MaybeUninit<u32>` has the same memory layout as `[MaybeUninit<u8>; 4]`
        // - The buffer is a `Box<[MaybeUninit<u32>]>` of length N / 4, so it is valid for N bytes.
        unsafe {
            std::slice::from_raw_parts_mut(self.buffer.as_mut_ptr().cast::<MaybeUninit<u8>>(), N)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::kernel_buffer::AlignedBuffer;

    #[test]
    #[should_panic(expected = "The buffer is not aligned")]
    fn fail_when_not_multiple_of_alignment() {
        let _buffer = AlignedBuffer::<4, 5>::new();
    }
}
