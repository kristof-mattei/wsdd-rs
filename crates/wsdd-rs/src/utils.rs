use tokio::task::JoinHandle;

use crate::shutdown::Shutdown;

pub mod env;
pub mod task;

pub async fn flatten_shutdown_handle(
    handle: JoinHandle<Result<!, Shutdown>>,
) -> Result<!, Shutdown> {
    handle.await?
}

/// Utility struct to format the elements using the Display trait instead of the Debug trait.
pub struct SliceDisplay<'s, T>(pub &'s [T]);

impl<T: std::fmt::Display> std::fmt::Display for SliceDisplay<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut iter = self.0.iter();

        f.write_str("[")?;

        if let Some(first) = iter.next() {
            write!(f, "{}", first)?;

            for next in iter {
                write!(f, ", {}", next)?;
            }
        }

        f.write_str("]")
    }
}

/// `const` cast a `u16` to `usize`. `usize::from(u16)` is not `const` yet.
pub const fn u16_to_usize(from: u16) -> usize {
    #[expect(clippy::as_conversions, reason = "Same as `usize::from(u16)`")]
    {
        from as usize
    }
}

/// `const` cast a `u32` to `usize`. `usize::try_from(u32)` returns a `Result` on every target.
pub const fn u32_to_usize(from: u32) -> usize {
    const _: () = assert!(
        size_of::<usize>() >= size_of::<u32>(),
        "wsdd-rs requires a `usize` of at least 32 bits"
    );

    #[expect(
        clippy::as_conversions,
        reason = "Validated that `u32` fits in `usize`"
    )]
    {
        from as usize
    }
}

/// `const` cast an `i32` to `u8`. `u8::try_from(i32)` is not `const` yet.
///
/// # Panics
///
/// If `from` is outside `0..=0xFF`.
pub const fn i32_to_u8(from: i32) -> u8 {
    assert!(matches!(from, 0..=0xFF), "`from` must fit in a `u8`");

    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Validated that `from` fits in `u8`"
    )]
    {
        from as u8
    }
}

/// `const` cast an `i32` to `u16`. `u16::try_from(i32)` is not `const` yet.
///
/// # Panics
///
/// If `from` is outside `0..=0xFFFF`.
pub const fn i32_to_u16(from: i32) -> u16 {
    assert!(matches!(from, 0..=0xFFFF), "`from` must fit in a `u16`");

    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "Validated that `from` fits in `u16`"
    )]
    {
        from as u16
    }
}

/// `const` cast a `usize` to `u16`. `u16::try_from(usize)` is not `const` yet.
///
/// # Panics
///
/// If `from` is outside `0..=0xFFFF`.
pub const fn usize_to_u16(from: usize) -> u16 {
    assert!(matches!(from, 0..=0xFFFF), "`from` must fit in a `u16`");

    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "Validated that `from` fits in `u16`"
    )]
    {
        from as u16
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::utils::SliceDisplay;

    #[test]
    fn slice_display_empty() {
        let empty: &[u32] = &[];
        assert_eq!(SliceDisplay(empty).to_string(), "[]");
    }

    #[test]
    fn slice_display_single() {
        assert_eq!(SliceDisplay(&[42_u32]).to_string(), "[42]");
    }

    #[test]
    fn slice_display_multiple() {
        assert_eq!(SliceDisplay(&[1_u32, 2, 3]).to_string(), "[1, 2, 3]");
    }
}
