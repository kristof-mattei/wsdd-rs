use std::mem::{MaybeUninit, size_of};
use std::ops::{Deref, DerefMut};
use std::slice::SliceIndex;

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

impl<const A: usize, const N: usize, I> std::ops::Index<I> for AlignedBuffer<A, N>
where
    ConstToType<A>: MapConstToType,
    I: SliceIndex<[MaybeUninit<u8>]>,
{
    type Output = I::Output;

    fn index(&self, index: I) -> &I::Output {
        &AsRef::<[MaybeUninit<u8>]>::as_ref(&(**self))[index]
    }
}

impl<const A: usize, const N: usize, I> std::ops::IndexMut<I> for AlignedBuffer<A, N>
where
    ConstToType<A>: MapConstToType,
    I: SliceIndex<[MaybeUninit<u8>]>,
{
    fn index_mut(&mut self, index: I) -> &mut I::Output {
        &mut AsMut::<[MaybeUninit<u8>]>::as_mut(&mut **self)[index]
    }
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
            N.is_multiple_of(Self::MAPPED_TYPE_SIZE),
            "N must be a multiple of the mapped type size"
        );

        let len = N / Self::MAPPED_TYPE_SIZE;

        Self {
            buffer: Box::new_uninit_slice(len),
        }
    }
}

impl<const A: usize, const N: usize> Deref for AlignedBuffer<A, N>
where
    ConstToType<A>: MapConstToType,
{
    type Target = [MaybeUninit<u8>];

    fn deref(&self) -> &Self::Target {
        let ptr = self.buffer.as_ptr();

        // SAFETY: The underlying buffer is of `N / size_of::<A>()`, so the buffer is valid for a length of `N`
        unsafe { std::slice::from_raw_parts(ptr.cast::<MaybeUninit<u8>>(), N) }
    }
}

impl<const A: usize, const N: usize> DerefMut for AlignedBuffer<A, N>
where
    ConstToType<A>: MapConstToType,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        let mut_ptr = self.buffer.as_mut_ptr();

        // SAFETY: The underlying buffer is of `N / size_of::<A>()`, so the buffer is valid for a length of `N`
        unsafe { std::slice::from_raw_parts_mut(mut_ptr.cast::<MaybeUninit<u8>>(), N) }
    }
}

#[cfg(test)]
mod tests {
    use crate::kernel_buffer::AlignedBuffer;

    #[test]
    #[should_panic(expected = "N must be a multiple of the mapped type size")]
    fn fail_when_not_multiple_of_alignment() {
        let _buffer = AlignedBuffer::<4, 5>::new();
    }
}
