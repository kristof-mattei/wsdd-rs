use std::hash::Hash;

use delegate::delegate;
use ringmap::set::{IntoIter, Iter};
use ringmap::{Equivalent, RingSet};

pub struct MaxSizeDeque<T> {
    inner: RingSet<T>,
    maximum_size: usize,
}

impl<T> MaxSizeDeque<T> {
    delegate! {
        to self.inner {
            pub fn contains<Q>(&self, value: &Q) -> bool
            where
                Q: ?Sized + Hash + Equivalent<T>;
            pub fn len(&self) -> usize;
            #[cfg_attr(not(test), expect(unused, reason = "API"))]
            pub fn iter(&self) -> Iter<'_, T>;
            #[cfg_attr(not(test), expect(unused, reason = "API"))]
            pub fn into_iter(self) -> IntoIter<T>;
        }
    }

    pub fn new(maximum_size: usize) -> Self {
        Self {
            inner: RingSet::new(),
            maximum_size,
        }
    }

    /// Appends the value into the set.
    ///
    /// If an equivalent item already exists in the set, it returns
    /// `false`, leaving the original value in the set and without
    /// altering its insertion order. Otherwise, it inserts the new
    /// item at the back, ensures the `maximum_size` is adhered to
    /// and returns `true`.
    ///
    /// Computes in **O(1)** time (amortized average).
    pub fn push_back(&mut self, value: T) -> bool
    where
        T: Eq + Hash,
    {
        let (_, was_inserted) = self.inner.push_back(value);

        if !was_inserted {
            return false;
        }

        if self.len() > self.maximum_size {
            self.inner.pop_front();
        }

        true
    }

    /// Prepends the value into the set.
    ///
    /// If an equivalent item already exists in the set, it returns
    /// `false`, leaving the original value in the set and without
    /// altering its insertion order. Otherwise, it inserts the new
    /// item at the front, ensures the `maximum_size` is adhered to
    /// and returns `true`.
    ///
    /// Computes in **O(1)** time (amortized average).
    #[cfg_attr(not(test), expect(unused, reason = ""))]
    pub fn push_front(&mut self, value: T) -> bool
    where
        T: Eq + Hash,
    {
        let (_, was_inserted) = self.inner.push_front(value);

        if !was_inserted {
            return false;
        }

        if self.len() > self.maximum_size {
            self.inner.pop_back();
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::max_size_deque::MaxSizeDeque;

    #[test]
    fn no_slots() {
        let mut max_size_deque = MaxSizeDeque::<usize>::new(0);

        assert!(max_size_deque.inner.is_empty());

        max_size_deque.push_back(5);

        assert!(max_size_deque.inner.is_empty());
    }

    #[test]
    fn push_back_deletes_from_front() {
        let mut max_size_deque = MaxSizeDeque::<usize>::new(5);
        assert!(max_size_deque.inner.is_empty());

        for i in 0..5 {
            max_size_deque.push_back(i);
        }

        assert_eq!(max_size_deque.len(), 5);

        max_size_deque.push_back(5);

        assert_eq!(max_size_deque.len(), 5);

        // we expect 0 to have fallen off
        assert!(max_size_deque.iter().any(|v| *v != 0));
    }

    #[test]
    fn push_front_deletes_from_back() {
        let mut max_size_deque = MaxSizeDeque::<usize>::new(5);
        assert!(max_size_deque.inner.is_empty());

        for i in 1..6 {
            max_size_deque.push_back(i);
        }

        assert_eq!(max_size_deque.len(), 5);

        max_size_deque.push_front(0);

        assert_eq!(max_size_deque.len(), 5);

        // we expect 0 to have fallen off
        assert!(max_size_deque.iter().any(|v| *v != 6));
    }

    #[test]
    fn push_back_duplicate_doesnt_do_anything() {
        let mut max_size_deque = MaxSizeDeque::<usize>::new(5);
        assert!(max_size_deque.inner.is_empty());

        for i in 0..5 {
            max_size_deque.push_back(i);
        }

        assert_eq!(max_size_deque.len(), 5);

        max_size_deque.push_back(3);

        assert_eq!(max_size_deque.len(), 5);

        // we expect the deque not to have changed
        assert_eq!(
            &max_size_deque.into_iter().collect::<Vec<_>>(),
            &[0_usize, 1, 2, 3, 4][..]
        );
    }

    #[test]
    fn push_front_duplicate_doesnt_do_anything() {
        let mut max_size_deque = MaxSizeDeque::<usize>::new(5);
        assert!(max_size_deque.inner.is_empty());

        for i in 0..5 {
            max_size_deque.push_back(i);
        }

        assert_eq!(max_size_deque.len(), 5);

        max_size_deque.push_front(3);

        assert_eq!(max_size_deque.len(), 5);

        // we expect the deque not to have changed
        assert_eq!(
            &max_size_deque.into_iter().collect::<Vec<_>>(),
            &[0_usize, 1, 2, 3, 4][..]
        );
    }
}
