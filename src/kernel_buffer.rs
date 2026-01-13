use std::mem::MaybeUninit;
use std::ops::{Index, IndexMut};
use std::slice::SliceIndex;

use bytes::BufMut;
use bytes::buf::UninitSlice;

#[repr(align(4))]
pub struct KernelBuffer<const N: usize>([MaybeUninit<u8>; N]);

impl<const N: usize> KernelBuffer<N> {
    pub fn new() -> Self {
        Self([MaybeUninit::<u8>::uninit(); N])
    }

    pub fn new_boxed() -> Box<Self> {
        Box::new(Self::new())
    }
}

impl<I, const N: usize> Index<I> for KernelBuffer<N>
where
    I: SliceIndex<[MaybeUninit<u8>]>,
{
    type Output = I::Output;

    fn index(&self, index: I) -> &Self::Output {
        self.0.index(index)
    }
}

impl<I, const N: usize> IndexMut<I> for KernelBuffer<N>
where
    I: SliceIndex<[MaybeUninit<u8>]>,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        self.0.index_mut(index)
    }
}

// SAFETY: Passing through to the underlying buffer
unsafe impl<const N: usize> BufMut for KernelBuffer<N> {
    #[inline]
    fn remaining_mut(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        UninitSlice::uninit(&mut self.0[..])
    }

    #[inline]
    unsafe fn advance_mut(&mut self, cnt: usize) {
        let mut buffer = &mut self.0[..];

        // SAFETY: Passing through to the underlying buffer
        unsafe { BufMut::advance_mut(&mut buffer, cnt) }
    }

    #[inline]
    fn put_slice(&mut self, src: &[u8]) {
        let mut buffer = &mut self.0[..];

        BufMut::put_slice(&mut buffer, src);
    }

    #[inline]
    fn put_bytes(&mut self, val: u8, cnt: usize) {
        let mut buffer = &mut self.0[..];

        BufMut::put_bytes(&mut buffer, val, cnt);
    }
}
