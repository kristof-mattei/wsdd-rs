use std::collections::VecDeque;
use std::collections::vec_deque::Iter;

use delegate::delegate;

pub struct MaxSizeDeque<T> {
    inner: VecDeque<T>,
    max_size: usize,
}

impl<T> MaxSizeDeque<T> {
    delegate! {
        to self.inner {
            pub fn iter(&self) -> Iter<'_, T>;
        }
    }

    pub fn new(max_size: usize) -> Self {
        Self {
            inner: VecDeque::new(),
            max_size,
        }
    }

    pub fn push_back(&mut self, value: T) {
        self.inner.push_back(value);

        if self.inner.len() > self.max_size {
            self.inner.pop_front();
        }
    }

    #[cfg_attr(not(test), expect(unused, reason = ""))]
    pub fn push_front(&mut self, value: T) {
        self.inner.push_front(value);

        if self.inner.len() > self.max_size {
            self.inner.pop_back();
        }
    }
}

impl<T> MaxSizeDeque<T> where T: Eq {}

#[cfg(test)]
mod tests {
    use crate::max_size_deque::MaxSizeDeque;
    use pretty_assertions::assert_eq;

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

        assert_eq!(max_size_deque.inner.len(), 5);

        max_size_deque.push_back(5);

        assert_eq!(max_size_deque.inner.len(), 5);

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

        assert_eq!(max_size_deque.inner.len(), 5);

        max_size_deque.push_front(0);

        assert_eq!(max_size_deque.inner.len(), 5);

        // we expect 0 to have fallen off
        assert!(max_size_deque.iter().any(|v| *v != 6));
    }
}
