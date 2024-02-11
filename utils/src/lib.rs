#![no_std]

// gen_xor_key isn't required to be a shared module, as it's only used in the shellcode generator

const HASH_KEY: usize = 5381;

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
