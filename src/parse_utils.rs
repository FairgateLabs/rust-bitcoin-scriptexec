use bitcoin::{opcodes::{self, all::OP_PUSHBYTES_0}, script::{Builder, PushBytes}, Opcode, ScriptBuf};
use hex_conservative::HexToBytesIter;
use core::str::FromStr;

use bitcoin_opcode_utils::{from_str, is_push_bytes, is_push_data, OP_PUSHDATA1_CODE};

pub fn parse_asm(asm: &str) -> Result<ScriptBuf, ParseAsmError> {
    fn err(position: (usize, usize), kind: AsmParseErrorKind) -> ParseAsmError {
        ParseAsmError { position, kind }
    }

    let mut buf = Vec::with_capacity(65);
    let mut builder = Builder::new();
    let mut words = iter_words(asm);
    while let Some((pos, mut word)) = words.next() {
        // We have this special case in our formatter.
        if word == "OP_0" {
            builder = builder.push_opcode(OP_PUSHBYTES_0);
            continue;
        }

        if let Ok(op) = from_str(word) {
            // check for push opcodes
            if is_push_bytes(op) || is_push_data(op) {
                let (next, push) = words.next().ok_or(err(pos, AsmParseErrorKind::UnexpectedEOF))?;
                if !try_parse_raw_hex(push, &mut buf) {
                    return Err(err(next, AsmParseErrorKind::InvalidHex));
                }

                // NB our API doesn't actually allow us to make byte pushes with
                // non-minimal length prefix, so we can only check and error if
                // the user wants a non-minimal push
                let expected_push_op = match buf.len() {
                    n if n < OP_PUSHDATA1_CODE as usize => {
                        Opcode::from(n as u8)
                    }
                    n if n < 0x100 => {
                        opcodes::all::OP_PUSHDATA1
                    }
                    n if n < 0x10000 => {
                        opcodes::all::OP_PUSHDATA2
                    }
                    n if n < 0x100000000 => {
                        opcodes::all::OP_PUSHDATA4
                    }
                    _ => return Err(err(next, AsmParseErrorKind::PushExceedsMaxSize)),
                };
                if op != expected_push_op {
                    return Err(err(pos, AsmParseErrorKind::NonMinimalBytePush));
                }

                let push = <&PushBytes>::try_from(&buf[..])
                    .map_err(|_| err(next, AsmParseErrorKind::PushExceedsMaxSize))?;
                builder = builder.push_slice(push);
            } else {
                builder = builder.push_opcode(op);
            }
            continue;
        }

        // Not an opcode, try to interpret as number or push.

        if word.starts_with('<') && word.ends_with('>') {
            word = &word[1..word.len()-1];
        }

        // Try a number.
        if let Ok(i) = i64::from_str(&word) {
            builder = builder.push_int(i);
            continue;
        }

        // Finally, try hex in various forms.
        if word.starts_with("0x") {
            word = &word[2..];
        }

        if try_parse_raw_hex(word, &mut buf) {
            let push = <&PushBytes>::try_from(&buf[..])
                .map_err(|_| err(pos, AsmParseErrorKind::PushExceedsMaxSize))?;
            builder = builder.push_slice(push);
        } else {
            return Err(err(pos, AsmParseErrorKind::UnknownInstruction));
        }
    }

    Ok(builder.into_script())
}

/// Try to parse raw hex bytes and push them into the buffer.
fn try_parse_raw_hex(hex: &str, buf: &mut Vec<u8>) -> bool {
    buf.clear();
    let iter = match HexToBytesIter::new(hex) {
        Ok(i) => i,
        Err(_) => return false,
    };
    for item in iter {
        let item = match item {
            Ok(i) => i,
            Err(_) => return false,
        };
        buf.push(item);
    }
    true
}

/// Create an iterator over instruction words and their position in the file.
fn iter_words(asm: &str) -> impl Iterator<Item = ((usize, usize), &str)> {
    asm.lines().enumerate().flat_map(|(line_idx, line)| {
        let content = line.splitn(2, "#").next().unwrap().splitn(2, "//").next().unwrap();
        content.split_whitespace().enumerate().map(move |(word_idx, word)| {
            ((line_idx, word_idx), word)
        })
    })
}

/// Error from parsing Script ASM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseAsmError {
    /// The position of the instruction that caused the error.
    ///
    /// The value is (line, word) with word incremented after
    /// every chunk of whitespace.
    pub position: (usize, usize),

    /// The kind of error that occurred.
    pub kind: AsmParseErrorKind,
}

/// The different kinds of [AsmParseError] that can occur.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AsmParseErrorKind {
    /// ASM ended unexpectedly.
    UnexpectedEOF,
    /// We were not able to interpret the instruction.
    UnknownInstruction,
    /// Invalid hexadecimal bytes.
    InvalidHex,
    /// Byte push exceeding the maximum size.
    PushExceedsMaxSize,
    /// ASM contains a byte push with non-minimal size prefix.
    ///
    /// This is not necessarily invalid, but we can't construct such pushes.
    NonMinimalBytePush,
}