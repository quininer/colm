#![allow(dead_code)]

use std::mem;
use libc::c_uchar;
use openssl::aes::AesKey;
use openssl_sys as ffi;
use colm::{ Colm, NONCE_LENGTH };
use colm::traits::{ KEY_LENGTH, BLOCK_LENGTH, BlockCipher as BC };

struct AesCipher(AesKey);

extern "C" {
    fn AES_encrypt(in_: *const c_uchar, out: *mut c_uchar, key: *const ffi::AES_KEY);
}

impl BC for AesCipher {
    const KEY_LENGTH: usize = 16;
    const BLOCK_LENGTH: usize = 16;

    fn new(key: &[u8; KEY_LENGTH]) -> Self {
        AesCipher(AesKey::new_encrypt(key).unwrap())
    }

    fn encrypt(&self, block: &mut [u8; BLOCK_LENGTH]) {
        fn into(key: &AesKey) -> &ffi::AES_KEY {
            struct AesKey2(ffi::AES_KEY);

            unsafe {
                &mem::transmute::<_, &AesKey2>(key).0
            }
        }

        // why is openssl-sys not AES_encrypt?
        unsafe {
            AES_encrypt(block.as_ptr(), block.as_mut_ptr(), into(&self.0));
        }
    }

    fn decrypt(&self, _block: &mut [u8; BLOCK_LENGTH]) {
        unimplemented!()
    }
}

pub fn aead_encrypt(key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH], aad: &[u8], m: &[u8], c: &mut [u8]) {
    let cipher: Colm<AesCipher> = Colm::new(key);
    let mut process = cipher.encrypt(nonce, aad);

    let take =
        if m.len() % 16 == 0 { (m.len() / 16 - 1) * 16 }
        else { m.len() / 16 * 16 };

    let (input, input_remaining) = m.split_at(take);
    let (output, output_remaining) = c.split_at_mut(take);

    for (input, output) in input.chunks(BLOCK_LENGTH)
        .zip(output.chunks_mut(BLOCK_LENGTH))
    {
        let input = array_ref!(input, 0, BLOCK_LENGTH);
        let output = array_mut_ref!(output, 0, BLOCK_LENGTH);
        process.process(input, output);
    }
    process.finalize(input_remaining, output_remaining);
}

pub fn aead_decrypt(key: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH], aad: &[u8], c: &[u8], m: &mut [u8]) -> bool {
    let cipher: Colm<AesCipher> = Colm::new(key);
    let mut process = cipher.decrypt(nonce, aad);

    let take =
        if c.len() % 16 == 0 { (c.len() / 16 - 2) * 16 }
        else { (c.len() / 16 - 1) * 16 };

    let (input, input_remaining) = c.split_at(take);
    let (output, output_remaining) = m.split_at_mut(take);

    for (input, output) in input.chunks(BLOCK_LENGTH)
        .zip(output.chunks_mut(BLOCK_LENGTH))
    {
        let input = array_ref!(input, 0, BLOCK_LENGTH);
        let output = array_mut_ref!(output, 0, BLOCK_LENGTH);
        process.process(input, output);
    }
    process.finalize(input_remaining, output_remaining)
}
