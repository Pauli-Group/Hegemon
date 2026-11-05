//! Length-bounded containers: reject declared lengths before allocation.
use codec::{Compact, Decode, Encode, Input, Output};
use serde::{
    de::{Error as _, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{fmt, ops::Deref};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedVec<T, const MAX: usize>(Vec<T>);
impl<T, const MAX: usize> BoundedVec<T, MAX> {
    pub fn new(values: Vec<T>) -> Result<Self, &'static str> {
        if values.len() > MAX {
            return Err("bounded vector length exceeds limit");
        }
        Ok(Self(values))
    }
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}
impl<T, const MAX: usize> Default for BoundedVec<T, MAX> {
    fn default() -> Self {
        Self(Vec::new())
    }
}
impl<T, const MAX: usize> Deref for BoundedVec<T, MAX> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}
impl<T: Encode, const MAX: usize> Encode for BoundedVec<T, MAX> {
    fn size_hint(&self) -> usize {
        self.0.size_hint()
    }
    fn encode_to<O: Output + ?Sized>(&self, out: &mut O) {
        self.0.encode_to(out);
    }
}
impl<T: Decode, const MAX: usize> Decode for BoundedVec<T, MAX> {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let n = Compact::<u32>::decode(input)?.0 as usize;
        if n > MAX {
            return Err("bounded vector length exceeds limit".into());
        }
        let mut values = Vec::with_capacity(n);
        for _ in 0..n {
            values.push(T::decode(input)?);
        }
        Ok(Self(values))
    }
}
impl<T: Serialize, const MAX: usize> Serialize for BoundedVec<T, MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}
impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedVisitor<T, const N: usize>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for BoundedVisitor<T, N> {
            type Value = BoundedVec<T, N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "at most {N} elements")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                if seq.size_hint().is_some_and(|n| n > N) {
                    return Err(A::Error::custom("bounded vector length exceeds limit"));
                }
                let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(N));
                while let Some(value) = seq.next_element()? {
                    if values.len() == N {
                        return Err(A::Error::custom("bounded vector length exceeds limit"));
                    }
                    values.push(value);
                }
                Ok(BoundedVec(values))
            }
        }
        deserializer.deserialize_seq(BoundedVisitor::<T, MAX>(std::marker::PhantomData))
    }
}
