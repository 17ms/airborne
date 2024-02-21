#![no_std]

// gen_xor_key isn't required to be a shared module, as it's only used in the shellcode generator

const DELAY_FLAG: u32 = 0b0001;
const SHUFFLE_FLAG: u32 = 0b0010;
const UFN_FLAG: u32 = 0b0100;

const HASH_KEY: usize = 5381;

pub struct Flags {
    pub delay: bool,
    pub shuffle: bool,
    pub ufn: bool,
}

pub fn parse_u32_flag(flag: u32) -> Flags {
    Flags {
        delay: flag & DELAY_FLAG != 0,
        shuffle: flag & SHUFFLE_FLAG != 0,
        ufn: flag & UFN_FLAG != 0,
    }
}

pub fn create_u32_flag(delay: bool, shuffle: bool, ufn: bool) -> u32 {
    let mut flags = 0;

    if delay {
        flags |= DELAY_FLAG;
    }

    if shuffle {
        flags |= SHUFFLE_FLAG;
    }

    if ufn {
        flags |= UFN_FLAG;
    }

    flags
}

pub fn xor_cipher(data: &mut [u8], key: &[u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

pub fn calc_hash(buffer: &[u8]) -> u32 {
    let mut hash = HASH_KEY;

    for b in buffer {
        if *b == 0 {
            continue;
        }

        if (&b'a'..=&b'z').contains(&b) {
            hash = ((hash << 5).wrapping_add(hash)) + *b as usize - 0x20;
        } else {
            hash = ((hash << 5).wrapping_add(hash)) + *b as usize;
        }
    }

    hash as u32
}
