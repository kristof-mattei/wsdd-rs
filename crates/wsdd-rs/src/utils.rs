pub mod env;
pub mod task;

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

/// `const` cast a `u32` to `usize`.
/// Validates at compile time that `usize` is at least as wide as `u32`.
///
/// Even if `usize::try_from(u32)` ever becomes `const`, this is better, as it fails at compile time.
///
/// Why?
/// A raw `value as usize` at a call site is dangerous: if `value` is later widened to `u64` or `u128`, the cast silently truncates instead of erroring.
pub const fn u32_to_usize(from: u32) -> usize {
    const _: () = assert!(
        size_of::<usize>() >= size_of::<u32>(),
        "rtnetlink doesn't support 16-bit, so we don't either"
    );

    #[expect(
        clippy::as_conversions,
        reason = "Validated that `u32` fits in `usize`"
    )]
    {
        from as usize
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
