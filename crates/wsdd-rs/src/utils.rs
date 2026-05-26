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

// because `From::from` cannot be called in `const` yet
pub const fn u16_to_usize(from: u16) -> usize {
    #[expect(clippy::as_conversions, reason = "Same as `usize::from(u16)`")]
    {
        from as usize
    }
}

// because `From::from` cannot be called in `const` yet
// having raw `as usize` is dangerous, as copy-pasting might
// do it on a `value_u64 as usize` on a 32-bit platform which truncates
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
