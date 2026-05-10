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

// Ideally this would take a type `T` and derive the alignment internally:
//     `pub struct AlignedBuffer<T> where ConstToType<{ align_of::<T>() }>: MapConstToType`
// Blocked on `generic_const_exprs` (rust-lang/rust#76560).
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

    /// Allocates a buffer of at least `minimum_length` bytes, aligned to `A`.
    /// If `minimum_length` is not a multiple of `A`, the byte length is rounded up to the next multiple of `A`.
    pub fn new(minimum_length: usize) -> Self {
        const {
            assert!(
                align_of::<<ConstToType<A> as MapConstToType>::Output>() >= A,
                "backing type alignment is smaller than requested A",
            );
        }

        Self {
            buffer: Box::new_uninit_slice(minimum_length.div_ceil(Self::MAPPED_TYPE_SIZE)),
        }
    }
}

impl<const A: usize> Deref for AlignedBuffer<A>
where
    ConstToType<A>: MapConstToType,
{
    type Target = [MaybeUninit<u8>];

    fn deref(&self) -> &Self::Target {
        let ptr = self.buffer.as_ptr();

        // SAFETY: `self.buffer` is a contiguous allocation of exactly
        // `self.buffer.len() * MAPPED_TYPE_SIZE` bytes. Alignment is trivially satisfied
        // (`MaybeUninit<u8>` is 1-aligned), and `MaybeUninit<u8>` has no validity
        // invariants, so any byte contents, including uninitialized, are fine.
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

        // SAFETY: `self.buffer` is a contiguous allocation of exactly
        // `self.buffer.len() * MAPPED_TYPE_SIZE` bytes. Alignment is trivially satisfied
        // (`MaybeUninit<u8>` is 1-aligned), and `MaybeUninit<u8>` has no validity
        // invariants, so any byte contents, including uninitialized, are fine.
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
    use std::mem::MaybeUninit;

    use pretty_assertions::{assert_eq, assert_ne};

    use crate::kernel_buffer::AlignedBuffer;

    #[test]
    fn alignment_is_satisfied() {
        #[expect(clippy::modulo_one, reason = "valid for this test")]
        {
            assert_eq!((AlignedBuffer::<1>::new(8).as_ptr() as usize) % 1, 0);
        }
        assert_eq!((AlignedBuffer::<2>::new(8).as_ptr() as usize) % 2, 0);
        assert_eq!((AlignedBuffer::<4>::new(8).as_ptr() as usize) % 4, 0);
        assert_eq!((AlignedBuffer::<8>::new(16).as_ptr() as usize) % 8, 0);
        assert_eq!((AlignedBuffer::<16>::new(32).as_ptr() as usize) % 16, 0);
    }

    #[test]
    fn length_matches_request_when_aligned() {
        assert_eq!(AlignedBuffer::<1>::new(7).len(), 7);
        assert_eq!(AlignedBuffer::<4>::new(8).len(), 8);
        assert_eq!(AlignedBuffer::<16>::new(48).len(), 48);
    }

    #[test]
    fn length_rounds_up_when_not_aligned() {
        assert_eq!(AlignedBuffer::<4>::new(5).len(), 8);
        assert_eq!(AlignedBuffer::<8>::new(1).len(), 8);
        assert_eq!(AlignedBuffer::<16>::new(17).len(), 32);
    }

    #[test]
    fn successive_calls_dont_alias() {
        let a = AlignedBuffer::<4>::new(16);
        let b = AlignedBuffer::<4>::new(16);
        assert_ne!(a.as_ptr(), b.as_ptr());
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn indexing_past_length_panics() {
        let buf = AlignedBuffer::<4>::new(8);
        let _: MaybeUninit<u8> = buf[8];
    }
}
