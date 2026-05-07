use std::mem::{MaybeUninit, align_of, size_of};
use std::ops::{Deref, DerefMut};

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
pub struct AlignedBuffer<const A: usize>
where
    ConstToType<A>: MapConstToType,
{
    buffer: Box<[MaybeUninit<<ConstToType<A> as MapConstToType>::Output>]>,
}

impl<const A: usize> std::fmt::Debug for AlignedBuffer<A>
where
    ConstToType<A>: MapConstToType,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedBuffer")
            .field("buffer_len", &self.buffer.len())
            .finish()
    }
}

struct ConstToType<const U: usize>;

#[expect(
    dead_code,
    reason = "field exists only to give the struct its size; alignment comes from repr(align)"
)]
#[repr(align(1))]
struct Align1([u8; 1]);

#[expect(
    dead_code,
    reason = "field exists only to give the struct its size; alignment comes from repr(align)"
)]
#[repr(align(2))]
struct Align2([u8; 2]);

#[expect(
    dead_code,
    reason = "field exists only to give the struct its size; alignment comes from repr(align)"
)]
#[repr(align(4))]
struct Align4([u8; 4]);

#[expect(
    dead_code,
    reason = "field exists only to give the struct its size; alignment comes from repr(align)"
)]
#[repr(align(8))]
struct Align8([u8; 8]);

#[expect(
    dead_code,
    reason = "field exists only to give the struct its size; alignment comes from repr(align)"
)]
#[repr(align(16))]
struct Align16([u8; 16]);

impl private::Private for ConstToType<1> {}
impl MapConstToType for ConstToType<1> {
    type Output = Align1;
}

impl private::Private for ConstToType<2> {}
impl MapConstToType for ConstToType<2> {
    type Output = Align2;
}

impl private::Private for ConstToType<4> {}
impl MapConstToType for ConstToType<4> {
    type Output = Align4;
}

impl private::Private for ConstToType<8> {}
impl MapConstToType for ConstToType<8> {
    type Output = Align8;
}

impl private::Private for ConstToType<16> {}
impl MapConstToType for ConstToType<16> {
    type Output = Align16;
}

#[expect(
    private_bounds,
    reason = "Arbitrary implementations don't make sense and are not supported"
)]
impl<const A: usize> AlignedBuffer<A>
where
    ConstToType<A>: MapConstToType,
{
    const MAPPED_TYPE_SIZE: usize = size_of::<<ConstToType<A> as MapConstToType>::Output>();

    pub fn new(len: usize) -> Result<Self, &'static str> {
        const {
            assert!(
                align_of::<<ConstToType<A> as MapConstToType>::Output>() >= A,
                "backing type alignment is smaller than requested A",
            );
        }

        if !len.is_multiple_of(Self::MAPPED_TYPE_SIZE) {
            return Err("len must be a multiple of the mapped type size");
        }

        let len = len / Self::MAPPED_TYPE_SIZE;

        Ok(Self {
            buffer: Box::new_uninit_slice(len),
        })
    }
}

impl<const A: usize> Deref for AlignedBuffer<A>
where
    ConstToType<A>: MapConstToType,
{
    type Target = [MaybeUninit<u8>];

    fn deref(&self) -> &Self::Target {
        let ptr = self.buffer.as_ptr();

        // SAFETY: `self.buffer` was allocated with `len / MAPPED_TYPE_SIZE` elements
        // of size `MAPPED_TYPE_SIZE`, so `self.buffer.len() * MAPPED_TYPE_SIZE` is exactly
        // the original `len` bytes covered contiguously by the allocation. Alignment is
        // trivially satisfied (`MaybeUninit<u8>` is 1-aligned), and `MaybeUninit<u8>` has
        // no validity invariants, so any byte contents, including uninitialized, are fine.
        unsafe {
            std::slice::from_raw_parts(
                ptr.cast::<MaybeUninit<u8>>(),
                self.buffer.len() * Self::MAPPED_TYPE_SIZE,
            )
        }
    }
}

impl<const A: usize> DerefMut for AlignedBuffer<A>
where
    ConstToType<A>: MapConstToType,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        let mut_ptr = self.buffer.as_mut_ptr();

        // SAFETY: `self.buffer` was allocated with `len / MAPPED_TYPE_SIZE` elements
        // of size `MAPPED_TYPE_SIZE`, so `self.buffer.len() * MAPPED_TYPE_SIZE` is exactly
        // the original `len` bytes covered contiguously by the allocation. Alignment is
        // trivially satisfied (`MaybeUninit<u8>` is 1-aligned), and `MaybeUninit<u8>` has
        // no validity invariants, so any byte contents, including uninitialized, are fine.
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
        assert_matches!(
            AlignedBuffer::<4>::new(5),
            Err("len must be a multiple of the mapped type size")
        );
    }
}
