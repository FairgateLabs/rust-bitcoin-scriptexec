use std::fmt;

use bitcoin::relative::{Height, LockTime, Time};

use crate::ExecError;

/// BIP-68 relative lock time disable flag mask.
pub(crate) const LOCK_TIME_DISABLE_FLAG_MASK: u32 = 0x80000000;

/// BIP-68 relative lock time type flag mask.
pub(crate) const LOCK_TYPE_MASK: u32 = 0x00400000;

/// Try to interpret the given number as a relative lock time.
#[inline]
pub fn from_num(num: i64) -> Option<LockTime> {
    let int = u32::try_from(num).ok()?;

    if int & LOCK_TIME_DISABLE_FLAG_MASK != 0 {
        return None;
    }

    let low16 = int as u16; // only need lowest 16 bits
    if int & LOCK_TYPE_MASK > 0 {
        Some(LockTime::from(Time::from_512_second_intervals(low16)))
    } else {
        Some(LockTime::from(Height::from(low16)))
    }
}

/// Ways parsing script integers might fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptIntError {
    /// Something did a non-minimal push; for more information see
    /// <https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#push-operators>
    NonMinimalPush,
    /// Tried to read an array off the stack as a number when it was more than 4 bytes.
    NumericOverflow,
}

impl fmt::Display for ScriptIntError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ScriptIntError::*;

        match *self {
            NonMinimalPush => f.write_str("non-minimal datapush"),
            NumericOverflow =>
                f.write_str("numeric overflow (number on stack larger than 4 bytes)"),
        }
    }
}

pub fn read_scriptint(item: &[u8], size: usize, minimal: bool) -> Result<i64, ExecError> {
    read_scriptint_size(item, size, minimal).map_err(|e| match e {
        ScriptIntError::NonMinimalPush => ExecError::MinimalData,
        // only possible if size is 4 or lower
        ScriptIntError::NumericOverflow => ExecError::ScriptIntNumericOverflow,
    })
}

/// Decodes an interger in script format with flexible size limit.
///
/// Note that in the majority of cases, you will want to use either
/// [read_scriptint] or [read_scriptint_non_minimal] instead.
///
/// Panics if max_size exceeds 8.
pub fn read_scriptint_size(v: &[u8], max_size: usize, minimal: bool) -> Result<i64, ScriptIntError> {
    assert!(max_size <= 8);

    if v.len() > max_size {
        return Err(ScriptIntError::NumericOverflow);
    }

    if v.is_empty() {
        return Ok(0);
    }

    if minimal {
        let last = match v.last() {
            Some(last) => last,
            None => return Ok(0),
        };
        // Comment and code copied from Bitcoin Core:
        // https://github.com/bitcoin/bitcoin/blob/447f50e4aed9a8b1d80e1891cda85801aeb80b4e/src/script/script.h#L247-L262
        // If the most-significant-byte - excluding the sign bit - is zero
        // then we're not minimal. Note how this test also rejects the
        // negative-zero encoding, 0x80.
        if (*last & 0x7f) == 0 {
            // One exception: if there's more than one byte and the most
            // significant bit of the second-most-significant-byte is set
            // it would conflict with the sign bit. An example of this case
            // is +-255, which encode to 0xff00 and 0xff80 respectively.
            // (big-endian).
            if v.len() <= 1 || (v[v.len() - 2] & 0x80) == 0 {
                return Err(ScriptIntError::NonMinimalPush);
            }
        }
    }

    Ok(scriptint_parse(v))
}

// Caller to guarantee that `v` is not empty.
fn scriptint_parse(v: &[u8]) -> i64 {
    let (mut ret, sh) = v.iter().fold((0, 0), |(acc, sh), n| (acc + ((*n as i64) << sh), sh + 8));
    if v[v.len() - 1] & 0x80 != 0 {
        ret &= (1 << (sh - 1)) - 1;
        ret = -ret;
    }
    ret
}

/// Returns minimally encoded scriptint as a byte vector.
pub fn scriptint_vec(n: i64) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let len = write_scriptint(&mut buf, n);
    buf[0..len].to_vec()
}

/// Encodes an integer in script(minimal CScriptNum) format.
///
/// Writes bytes into the buffer and returns the number of bytes written.
///
/// Note that `write_scriptint`/`read_scriptint` do not roundtrip if the value written requires
/// more than 4 bytes, this is in line with Bitcoin Core (see [`CScriptNum::serialize`]).
///
/// [`CScriptNum::serialize`]: <https://github.com/bitcoin/bitcoin/blob/8ae2808a4354e8dcc697f76bacc5e2f2befe9220/src/script/script.h#L345>
pub fn write_scriptint(out: &mut [u8; 8], n: i64) -> usize {
    let mut len = 0;
    if n == 0 {
        return len;
    }

    let neg = n < 0;

    let mut abs = n.unsigned_abs();
    while abs > 0xFF {
        out[len] = (abs & 0xFF) as u8;
        len += 1;
        abs >>= 8;
    }
    // If the number's value causes the sign bit to be set, we need an extra
    // byte to get the correct value and correct sign bit
    if abs & 0x80 != 0 {
        out[len] = abs as u8;
        len += 1;
        out[len] = if neg { 0x80u8 } else { 0u8 };
        len += 1;
    }
    // Otherwise we just set the sign bit ourselves
    else {
        abs |= if neg { 0x80 } else { 0 };
        out[len] = abs as u8;
        len += 1;
    }
    len
}
