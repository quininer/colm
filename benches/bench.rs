#![feature(test)]

extern crate test;

#[macro_use] extern crate arrayref;
extern crate libc;
extern crate openssl;
extern crate openssl_sys;
extern crate generic_array;
extern crate aes;
extern crate colm;

#[path = "../tests/aead/mod.rs"]
mod aead;

#[path = "../tests/aead/openssl.rs"]
mod openssl_backend;

use test::Bencher;
use colm::NONCE_LENGTH;
use colm::traits::{ KEY_LENGTH, BLOCK_LENGTH };
use aead::*;


#[bench]
fn aes128colm0_encrypt_bench(b: &mut Bencher) {
    let key = [0x42; KEY_LENGTH];
    let nonce = [0x43; NONCE_LENGTH];
    let m = [0x44; 1024];
    let mut c = vec![0; m.len() + BLOCK_LENGTH];

    b.bytes = m.len() as u64;
    b.iter(|| aead_encrypt(&key, &nonce, &m[..10], &m, &mut c));
}

#[bench]
fn aes128colm0_decrypt_bench(b: &mut Bencher) {
    let key = [0x43; KEY_LENGTH];
    let nonce = [0x44; NONCE_LENGTH];
    let m = [0x45; 1024];
    let mut p = [0; 1024];
    let mut c = vec![0; m.len() + BLOCK_LENGTH];
    aead_encrypt(&key, &nonce, &m[..10], &m, &mut c);

    b.bytes = c.len() as u64;
    b.iter(|| aead_decrypt(&key, &nonce, &m[..10], &c, &mut p));
}

#[bench]
fn openssl_aes128colm0_encrypt_bench(b: &mut Bencher) {
    let key = [0x42; KEY_LENGTH];
    let nonce = [0x43; NONCE_LENGTH];
    let m = [0x44; 1024];
    let mut c = vec![0; m.len() + BLOCK_LENGTH];

    b.bytes = m.len() as u64;
    b.iter(|| openssl_backend::aead_encrypt(&key, &nonce, &m[..10], &m, &mut c));
}
