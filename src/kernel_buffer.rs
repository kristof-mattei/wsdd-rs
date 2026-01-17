use std::mem::{MaybeUninit, size_of};
use std::ops::{Deref, DerefMut};
use std::slice::SliceIndex;

pub struct AlignedBuffer<T, const N: usize> {
    buffer: Box<[MaybeUninit<T>]>,
}

impl<T, const N: usize, I> std::ops::Index<I> for AlignedBuffer<T, N>
where
    I: SliceIndex<[MaybeUninit<u8>]>,
{
    type Output = I::Output;

    fn index(&self, index: I) -> &I::Output {
        &AsRef::<[MaybeUninit<u8>]>::as_ref(&(**self))[index]
    }
}

impl<T, const N: usize, I> std::ops::IndexMut<I> for AlignedBuffer<T, N>
where
    I: SliceIndex<[MaybeUninit<u8>]>,
{
    fn index_mut(&mut self, index: I) -> &mut I::Output {
        &mut AsMut::<[MaybeUninit<u8>]>::as_mut(&mut **self)[index]
    }
}

impl<T, const N: usize> AlignedBuffer<T, N> {
    const MAPPED_TYPE_SIZE: usize = size_of::<T>();

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

impl<T, const N: usize> Deref for AlignedBuffer<T, N> {
    type Target = [MaybeUninit<u8>];

    fn deref(&self) -> &Self::Target {
        let ptr = self.buffer.as_ptr();

        // SAFETY: The underlying buffer is of `N / size_of::<A>()`, so the buffer is valid for a length of `N`
        unsafe { std::slice::from_raw_parts(ptr.cast::<MaybeUninit<u8>>(), N) }
    }
}

impl<T, const N: usize> DerefMut for AlignedBuffer<T, N> {
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
        let _buffer = AlignedBuffer::<u32, 5>::new();
    }
}
