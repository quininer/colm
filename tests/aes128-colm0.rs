#![cfg(feature = "x16")]

#[macro_use] extern crate arrayref;
extern crate generic_array;
extern crate aes;
extern crate rand;
extern crate colm;

mod aead;

use rand::{ Rng, RngCore, thread_rng };
use colm::NONCE_LENGTH;
use colm::traits::{ BLOCK_LENGTH, KEY_LENGTH };
use aead::*;


#[test]
fn test() {
    const C: &[u8] = &[53, 244, 142, 175, 149, 85, 212, 74, 189, 185, 182, 250, 182, 106, 198, 140, 242, 79, 250, 44, 161, 52, 172, 62, 82, 9, 152, 148, 77, 76, 83, 39, 129, 24, 143, 43, 9, 100, 17, 3, 84, 145, 54, 102, 236, 104, 218, 197, 15, 150, 117, 160, 4, 255, 241, 215, 120, 143];
    const C2: &[u8] = &[209, 198, 126, 145, 80, 152, 227, 101, 42, 149, 162, 178, 117, 240, 195, 217, 19, 53, 49, 74, 70, 89, 213, 202, 147, 38, 111, 15, 143, 198, 7, 252, 122, 83, 72, 23, 169, 190, 11, 221, 115, 71, 95, 112, 190, 203, 216, 72];

    let key = b"keykeykeykeykey!";
    let nonce = b"nonce!!!";
    let m = b"The quick brown fox jumps over a lazy dog.";
    let mut c = vec![0; m.len() + BLOCK_LENGTH];


    // encrypt 1
    aead_encrypt(key, nonce, &m[..10], m, &mut c);
    assert_eq!(c, C);

    // encrypt 2
    let m2 = &m[..32];
    let mut c2 = vec![0; m2.len() + BLOCK_LENGTH];
    aead_encrypt(key, nonce, &m2[..16], m2, &mut c2);
    assert_eq!(c2, C2);


    // decrypt 1
    let mut p = vec![0; m.len()];
    let r = aead_decrypt(key, nonce, &m[..10], &c, &mut p);
    assert!(r);
    assert_eq!(&p[..], &m[..]);

    // decrypt 2
    let mut p2 = vec![0; m2.len()];
    let r = aead_decrypt(key, nonce, &m[..16], &c2, &mut p2);
    assert!(r);
    assert_eq!(&p2[..], &m2[..]);


    // decrypt 3
    let mut p = vec![0; m.len()];
    let mut m3 = m.clone();
    m3[7] ^= 0x42;
    let r = aead_decrypt(key, nonce, &m3[..10], &c, &mut p);
    assert!(!r);

    // decrypt 4
    let mut p2 = vec![0; m2.len()];
    c2[33] ^= 0x42;
    let r = aead_decrypt(key, nonce, &m[..16], &c2, &mut p2);
    assert!(!r);
}

#[test]
fn test_aead() {
    for i in 0..100 {
        let mut key = [0; KEY_LENGTH];
        let mut nonce = [0; NONCE_LENGTH];
        let mut aad = vec![0; thread_rng().gen_range(1, 128)];
        let mut m = vec![0; thread_rng().gen_range(1, 256)];
        let mut c = vec![0; m.len() + BLOCK_LENGTH];
        let mut p = vec![0; m.len()];

        thread_rng().fill_bytes(&mut key);
        thread_rng().fill_bytes(&mut nonce);
        thread_rng().fill_bytes(&mut aad);
        thread_rng().fill_bytes(&mut m);

        aead_encrypt(&key, &nonce, &aad, &m, &mut c);
        let r = aead_decrypt(&key, &nonce, &aad, &c, &mut p);
        assert!(r, "{} times", i);
        assert_eq!(p, m, "{} times", i);

        c[0] ^= 0x42;
        let r = aead_decrypt(&key, &nonce, &aad, &c, &mut p);
        assert!(!r, "{} times", i);
    }
}
