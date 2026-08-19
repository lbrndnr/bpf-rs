use crate::libbpf;
use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};

pub struct OpenObject {
    inner: MaybeUninit<libbpf::OpenObject>,
}

impl OpenObject {
    pub fn new() -> Self {
        Self {
            inner: MaybeUninit::uninit(),
        }
    }
}

impl Deref for OpenObject {
    type Target = MaybeUninit<libbpf::OpenObject>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for OpenObject {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

unsafe impl Send for OpenObject {}
