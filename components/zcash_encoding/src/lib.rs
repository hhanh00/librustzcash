//! *Zcash binary encodings.*
//!
//! `zcash_encoding` is a library that provides common encoding and decoding operations
//! for stable binary encodings used throughout the Zcash ecosystem.

#![no_std]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

#[cfg_attr(test, macro_use)]
extern crate alloc;

use alloc::vec::Vec;

use core::iter::FromIterator;
use core2::io::{self, Read, Write};

#[cfg(feature = "std")]
use nonempty::NonEmpty;

/// The maximum allowed value representable as a `[CompactSize]`
pub const MAX_COMPACT_SIZE: u32 = 0x02000000;

/// Namespace for functions for compact encoding of integers.
///
/// This codec requires integers to be in the range `0x0..=0x02000000`, for compatibility
/// with Zcash consensus rules.
pub struct CompactSize;

impl CompactSize {
    /// Reads an integer encoded in compact form.
    pub fn read<R: Read>(mut reader: R) -> io::Result<u64> {
        let mut flag_bytes = [0; 1];
        reader.read_exact(&mut flag_bytes)?;
        let flag = flag_bytes[0];

        let result = if flag < 253 {
            Ok(flag as u64)
        } else if flag == 253 {
            let mut bytes = [0; 2];
            reader.read_exact(&mut bytes)?;
            match u16::from_le_bytes(bytes) {
                n if n < 253 => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "non-canonical CompactSize",
                )),
                n => Ok(n as u64),
            }
        } else if flag == 254 {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes)?;
            match u32::from_le_bytes(bytes) {
                n if n < 0x10000 => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "non-canonical CompactSize",
                )),
                n => Ok(n as u64),
            }
        } else {
            let mut bytes = [0; 8];
            reader.read_exact(&mut bytes)?;
            match u64::from_le_bytes(bytes) {
                n if n < 0x100000000 => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "non-canonical CompactSize",
                )),
                n => Ok(n),
            }
        }?;

        match result {
            s if s > <u64>::from(MAX_COMPACT_SIZE) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CompactSize too large",
            )),
            s => Ok(s),
        }
    }

    /// Reads an integer encoded in contact form and performs checked conversion
    /// to the target type.
    pub fn read_t<R: Read, T: TryFrom<u64>>(mut reader: R) -> io::Result<T> {
        let n = Self::read(&mut reader)?;
        <T>::try_from(n).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "CompactSize value exceeds range of target type.",
            )
        })
    }

    /// Writes the provided `usize` value to the provided Writer in compact form.
    pub fn write<W: Write>(mut writer: W, size: usize) -> io::Result<()> {
        match size {
            s if s < 253 => writer.write_all(&[s as u8]),
            s if s <= 0xFFFF => {
                writer.write_all(&[253])?;
                writer.write_all(&(s as u16).to_le_bytes())
            }
            s if s <= 0xFFFFFFFF => {
                writer.write_all(&[254])?;
                writer.write_all(&(s as u32).to_le_bytes())
            }
            s => {
                writer.write_all(&[255])?;
                writer.write_all(&(s as u64).to_le_bytes())
            }
        }
    }

    /// Returns the number of bytes needed to encode the given size in compact form.
    pub fn serialized_size(size: usize) -> usize {
        match size {
            s if s < 253 => 1,
            s if s <= 0xFFFF => 3,
            s if s <= 0xFFFFFFFF => 5,
            _ => 9,
        }
    }
}

/// Namespace for functions that perform encoding of vectors.
///
/// The length of a vector is restricted to at most `0x02000000`, for compatibility with
/// the Zcash consensus rules.
pub struct Vector;

impl Vector {
    /// Reads a vector, assuming the encoding written by [`Vector::write`], using the provided
    /// function to decode each element of the vector.
    pub fn read<R: Read, E, F>(reader: R, func: F) -> io::Result<Vec<E>>
    where
        F: Fn(&mut R) -> io::Result<E>,
    {
        Self::read_collected(reader, func)
    }

    /// Reads a CompactSize-prefixed series of elements into a collection, assuming the encoding
    /// written by [`Vector::write`], using the provided function to decode each element.
    pub fn read_collected<R: Read, E, F, O: FromIterator<E>>(reader: R, func: F) -> io::Result<O>
    where
        F: Fn(&mut R) -> io::Result<E>,
    {
        Self::read_collected_mut(reader, func)
    }

    /// Reads a CompactSize-prefixed series of elements into a collection, assuming the encoding
    /// written by [`Vector::write`], using the provided function to decode each element.
    pub fn read_collected_mut<R: Read, E, F, O: FromIterator<E>>(
        mut reader: R,
        func: F,
    ) -> io::Result<O>
    where
        F: FnMut(&mut R) -> io::Result<E>,
    {
        let count: usize = CompactSize::read_t(&mut reader)?;
        Array::read_collected_mut(reader, count, func)
    }

    /// Writes a slice of values by writing [`CompactSize`]-encoded integer specifying the length
    /// of the slice to the stream, followed by the encoding of each element of the slice as
    /// performed by the provided function.
    pub fn write<W: Write, E, F>(writer: W, vec: &[E], func: F) -> io::Result<()>
    where
        F: Fn(&mut W, &E) -> io::Result<()>,
    {
        Self::write_sized(writer, vec.iter(), func)
    }

    /// Writes a NonEmpty container of values to the stream using the same encoding as
    /// `[Vector::write]`
    #[cfg(feature = "std")]
    pub fn write_nonempty<W: Write, E, F>(
        mut writer: W,
        vec: &NonEmpty<E>,
        func: F,
    ) -> io::Result<()>
    where
        F: Fn(&mut W, &E) -> io::Result<()>,
    {
        CompactSize::write(&mut writer, vec.len())?;
        vec.iter().try_for_each(|e| func(&mut writer, e))
    }

    /// Writes an iterator of values by writing [`CompactSize`]-encoded integer specifying
    /// the length of the iterator to the stream, followed by the encoding of each element
    /// of the iterator as performed by the provided function.
    pub fn write_sized<W: Write, E, F, I: Iterator<Item = E> + ExactSizeIterator>(
        mut writer: W,
        mut items: I,
        func: F,
    ) -> io::Result<()>
    where
        F: Fn(&mut W, E) -> io::Result<()>,
    {
        CompactSize::write(&mut writer, items.len())?;
        items.try_for_each(|e| func(&mut writer, e))
    }

    /// Returns the serialized size of a vector of `u8` as written by `[Vector::write]`.
    pub fn serialized_size_of_u8_vec(vec: &[u8]) -> usize {
        let length = vec.len();
        CompactSize::serialized_size(length) + length
    }
}

/// Namespace for functions that perform encoding of array contents.
///
/// This is similar to the [`Vector`] encoding except that no length information is
/// written as part of the encoding, so length must be statically known or obtained from
/// other parts of the input stream.
pub struct Array;

impl Array {
    /// Reads `count` elements from a stream into a vector, assuming the encoding written by
    /// [`Array::write`], using the provided function to decode each element.
    pub fn read<R: Read, E, F>(reader: R, count: usize, func: F) -> io::Result<Vec<E>>
    where
        F: Fn(&mut R) -> io::Result<E>,
    {
        Self::read_collected(reader, count, func)
    }

    /// Reads `count` elements into a collection, assuming the encoding written by
    /// [`Array::write`], using the provided function to decode each element.
    pub fn read_collected<R: Read, E, F, O: FromIterator<E>>(
        reader: R,
        count: usize,
        func: F,
    ) -> io::Result<O>
    where
        F: Fn(&mut R) -> io::Result<E>,
    {
        Self::read_collected_mut(reader, count, func)
    }

    /// Reads `count` elements into a collection, assuming the encoding written by
    /// [`Array::write`], using the provided function to decode each element.
    pub fn read_collected_mut<R: Read, E, F, O: FromIterator<E>>(
        mut reader: R,
        count: usize,
        mut func: F,
    ) -> io::Result<O>
    where
        F: FnMut(&mut R) -> io::Result<E>,
    {
        (0..count).map(|_| func(&mut reader)).collect()
    }

    /// Writes an iterator full of values to a stream by sequentially
    /// encoding each element using the provided function.
    pub fn write<W: Write, E, I: IntoIterator<Item = E>, F>(
        mut writer: W,
        vec: I,
        func: F,
    ) -> io::Result<()>
    where
        F: Fn(&mut W, &E) -> io::Result<()>,
    {
        vec.into_iter().try_for_each(|e| func(&mut writer, &e))
    }
}

/// Namespace for functions that perform encoding of [`Option`] values.
pub struct Optional;

impl Optional {
    /// Reads an optional value, assuming the encoding written by [`Optional::write`], using the
    /// provided function to decode the contained element if present.
    pub fn read<R: Read, T, F>(mut reader: R, func: F) -> io::Result<Option<T>>
    where
        F: Fn(R) -> io::Result<T>,
    {
        let mut bytes = [0; 1];
        reader.read_exact(&mut bytes)?;
        match bytes[0] {
            0 => Ok(None),
            1 => Ok(Some(func(reader)?)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "non-canonical Option<T>",
            )),
        }
    }

    /// Writes an optional value to a stream by writing a flag byte with a value of 0 if no value
    /// is present, or 1 if there is a value, followed by the encoding of the contents of the
    /// option as performed by the provided function.
    pub fn write<W: Write, T, F>(mut writer: W, val: Option<T>, func: F) -> io::Result<()>
    where
        F: Fn(W, T) -> io::Result<()>,
    {
        match val {
            None => writer.write_all(&[0]),
            Some(e) => {
                writer.write_all(&[1])?;
                func(writer, e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Debug;

    #[test]
    fn compact_size() {
        fn eval<T: TryFrom<u64> + TryInto<usize> + Eq + Debug + Copy>(value: T, expected: &[u8])
        where
            <T as TryInto<usize>>::Error: Debug,
        {
            let mut data = vec![];
            let value_usize: usize = value.try_into().unwrap();
            CompactSize::write(&mut data, value_usize).unwrap();
            assert_eq!(&data[..], expected);
            let serialized_size = CompactSize::serialized_size(value_usize);
            assert_eq!(serialized_size, expected.len());
            let result: io::Result<T> = CompactSize::read_t(&data[..]);
            match result {
                Ok(n) => assert_eq!(n, value),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }

        eval(0, &[0]);
        eval(1, &[1]);
        eval(252, &[252]);
        eval(253, &[253, 253, 0]);
        eval(254, &[253, 254, 0]);
        eval(255, &[253, 255, 0]);
        eval(256, &[253, 0, 1]);
        eval(256, &[253, 0, 1]);
        eval(65535, &[253, 255, 255]);
        eval(65536, &[254, 0, 0, 1, 0]);
        eval(65537, &[254, 1, 0, 1, 0]);

        eval(33554432, &[254, 0, 0, 0, 2]);

        {
            let value = 33554433;
            let encoded = &[254, 1, 0, 0, 2][..];
            let mut data = vec![];
            CompactSize::write(&mut data, value).unwrap();
            assert_eq!(&data[..], encoded);
            let serialized_size = CompactSize::serialized_size(value);
            assert_eq!(serialized_size, encoded.len());
            assert!(CompactSize::read(encoded).is_err());
        }
    }

    #[allow(clippy::useless_vec)]
    #[test]
    fn vector() {
        macro_rules! eval {
            ($value:expr, $expected:expr) => {
                let mut data = vec![];
                Vector::write(&mut data, &$value, |w, e| w.write_all(&[*e])).unwrap();
                assert_eq!(&data[..], &$expected[..]);
                let serialized_size = Vector::serialized_size_of_u8_vec(&$value);
                assert_eq!(serialized_size, $expected.len());
                match Vector::read(&data[..], |r| {
                    let mut bytes = [0; 1];
                    r.read_exact(&mut bytes).map(|_| bytes[0])
                }) {
                    Ok(v) => assert_eq!(v, $value),
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            };
        }

        eval!(vec![], [0]);
        eval!(vec![0], [1, 0]);
        eval!(vec![1], [1, 1]);
        eval!(vec![5; 8], [8, 5, 5, 5, 5, 5, 5, 5, 5]);

        {
            // expected = [253, 4, 1, 7, 7, 7, ...]
            let mut expected = vec![7; 263];
            expected[0] = 253;
            expected[1] = 4;
            expected[2] = 1;

            eval!(vec![7; 260], expected);
        }
    }

    #[test]
    fn optional() {
        macro_rules! eval {
            ($value:expr, $expected:expr, $write:expr, $read:expr) => {
                let mut data = vec![];
                Optional::write(&mut data, $value, $write).unwrap();
                assert_eq!(&data[..], &$expected[..]);
                match Optional::read(&data[..], $read) {
                    Ok(v) => assert_eq!(v, $value),
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            };
        }

        macro_rules! eval_u8 {
            ($value:expr, $expected:expr) => {
                eval!($value, $expected, |w, e| w.write_all(&[e]), |mut r| {
                    let mut bytes = [0; 1];
                    r.read_exact(&mut bytes).map(|_| bytes[0])
                })
            };
        }

        macro_rules! eval_vec {
            ($value:expr, $expected:expr) => {
                eval!(
                    $value,
                    $expected,
                    |w, v| Vector::write(w, &v, |w, e| w.write_all(&[*e])),
                    |r| Vector::read(r, |r| {
                        let mut bytes = [0; 1];
                        r.read_exact(&mut bytes).map(|_| bytes[0])
                    })
                )
            };
        }

        eval_u8!(None, [0]);
        eval_u8!(Some(0), [1, 0]);
        eval_u8!(Some(1), [1, 1]);
        eval_u8!(Some(5), [1, 5]);

        eval_vec!(None as Option<Vec<_>>, [0]);
        eval_vec!(Some(vec![]), [1, 0]);
        eval_vec!(Some(vec![0]), [1, 1, 0]);
        eval_vec!(Some(vec![1]), [1, 1, 1]);
        eval_vec!(Some(vec![5; 8]), [1, 8, 5, 5, 5, 5, 5, 5, 5, 5]);
    }
}
