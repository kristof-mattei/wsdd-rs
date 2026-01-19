use std::mem::{MaybeUninit, size_of};
use std::ops::{Deref, DerefMut};
use std::slice::SliceIndex;

pub struct AlignedBuffer<T> {
    buffer: Box<[MaybeUninit<T>]>,
}

impl<T> std::fmt::Debug for AlignedBuffer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedBuffer")
            .field("buffer_len", &self.buffer.len())
            .finish()
    }
}

impl<T, I> std::ops::Index<I> for AlignedBuffer<T>
where
    I: SliceIndex<[MaybeUninit<u8>]>,
{
    type Output = I::Output;

    fn index(&self, index: I) -> &I::Output {
        &AsRef::<[MaybeUninit<u8>]>::as_ref(&(**self))[index]
    }
}

impl<T, I> std::ops::IndexMut<I> for AlignedBuffer<T>
where
    I: SliceIndex<[MaybeUninit<u8>]>,
{
    fn index_mut(&mut self, index: I) -> &mut I::Output {
        &mut AsMut::<[MaybeUninit<u8>]>::as_mut(&mut **self)[index]
    }
}

impl<T> AlignedBuffer<T> {
    const MAPPED_TYPE_SIZE: usize = size_of::<T>();

    pub fn new(len: usize) -> Result<Self, &'static str> {
        if !len.is_multiple_of(Self::MAPPED_TYPE_SIZE) {
            return Err("len must be a multiple of the mapped type size");
        }

        let len = len / Self::MAPPED_TYPE_SIZE;

        Ok(Self {
            buffer: Box::new_uninit_slice(len),
        })
    }
}

impl<T> Deref for AlignedBuffer<T> {
    type Target = [MaybeUninit<u8>];

    fn deref(&self) -> &Self::Target {
        let ptr = self.buffer.as_ptr();

        // SAFETY: The underlying buffer is of `N / size_of::<A>()`, so the buffer is valid for a length of `N`
        unsafe {
            std::slice::from_raw_parts(
                ptr.cast::<MaybeUninit<u8>>(),
                self.buffer.len() * Self::MAPPED_TYPE_SIZE,
            )
        }
    }
}

impl<T> DerefMut for AlignedBuffer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let mut_ptr = self.buffer.as_mut_ptr();

        // SAFETY: The underlying buffer is of `N / size_of::<A>()`, so the buffer is valid for a length of `N`
        unsafe {
            std::slice::from_raw_parts_mut(
                mut_ptr.cast::<MaybeUninit<u8>>(),
                self.buffer.len() * Self::MAPPED_TYPE_SIZE,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_matches;

    use crate::kernel_buffer::AlignedBuffer;

    #[test]
    fn fail_when_not_multiple_of_alignment() {
        let buffer = AlignedBuffer::<u32>::new(5);

        assert_matches!(
            buffer,
            Err("len must be a multiple of the mapped type size")
        );
    }
}
