use std::collections::{VecDeque, vec_deque::Iter};

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
        if self.inner.len() > self.max_size {
            self.inner.pop_front();
        }

        self.inner.push_back(value);
    }

    #[expect(unused)]
    pub fn push_front(&mut self, value: T) {
        if self.inner.len() > self.max_size {
            self.inner.pop_back();
        }

        self.inner.push_front(value);
    }
}

impl<T> MaxSizeDeque<T> where T: Eq {}
