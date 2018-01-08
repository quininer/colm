#![cfg(feature = "x16")]

#[macro_use] extern crate arrayref;
extern crate generic_array;
extern crate aesni;
extern crate colm;

use generic_array::GenericArray;
use aesni::{ BlockCipher, Aes128 };
use colm::Colm;
use colm::traits::{ KEY_LENGTH, BLOCK_LENGTH, BlockCipher as BC };


struct AesCipher(Aes128);

impl BC for AesCipher {
    const KEY_LENGTH: usize = 16;
    const BLOCK_LENGTH: usize = 16;

    fn new(key: &[u8; KEY_LENGTH]) -> Self {
        AesCipher(Aes128::new(GenericArray::from_slice(key)))
    }

    fn encrypt(&self, block: &mut [u8; BLOCK_LENGTH]) {
        self.0.encrypt_block(GenericArray::from_mut_slice(block));
    }

    fn decrypt(&self, block: &mut [u8; BLOCK_LENGTH]) {
        self.0.decrypt_block(GenericArray::from_mut_slice(block));
    }
}

#[test]
fn test() {
    const C: &[u8] = &[53, 244, 142, 175, 149, 85, 212, 74, 189, 185, 182, 250, 182, 106, 198, 140, 242, 79, 250, 44, 161, 52, 172, 62, 82, 9, 152, 148, 77, 76, 83, 39, 129, 24, 143, 43, 9, 100, 17, 3, 84, 145, 54, 102, 236, 104, 218, 197, 15, 150, 117, 160, 4, 255, 241, 215, 120, 143];
    const C2: &[u8] = &[209, 198, 126, 145, 80, 152, 227, 101, 42, 149, 162, 178, 117, 240, 195, 217, 19, 53, 49, 74, 70, 89, 213, 202, 147, 38, 111, 15, 143, 198, 7, 252, 122, 83, 72, 23, 169, 190, 11, 221, 115, 71, 95, 112, 190, 203, 216, 72];

    let key = b"keykeykeykeykey!";
    let nonce = b"nonce!!!";
    let m = b"The quick brown fox jumps over a lazy dog.";
    let mut c = vec![0; m.len() + BLOCK_LENGTH];


    // encrypt 1
    let cipher: Colm<AesCipher> = Colm::new(&key);
    let mut process = cipher.encrypt(&nonce, &m[..10]);

    {
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

    assert_eq!(c, C);


    // encrypt 2
    let m2 = &m[..32];
    let mut c2 = vec![0; m2.len() + BLOCK_LENGTH];
    let mut process = cipher.encrypt(&nonce, &m2[..16]);

    {
        let take =
            if m2.len() % 16 == 0 { (m2.len() / 16 - 1) * 16 }
            else { m2.len() / 16 * 16 };

        assert_eq!(take, 16);

        let (input, input_remaining) = m2.split_at(take);
        let (output, output_remaining) = c2.split_at_mut(take);

        for (input, output) in input.chunks(BLOCK_LENGTH)
            .zip(output.chunks_mut(BLOCK_LENGTH))
        {
            let input = array_ref!(input, 0, BLOCK_LENGTH);
            let output = array_mut_ref!(output, 0, BLOCK_LENGTH);
            process.process(input, output);
        }
        process.finalize(input_remaining, output_remaining);
    }

    assert_eq!(c2, C2);


    // decrypt 1
    let mut p = vec![0; m.len()];
    let mut process = cipher.decrypt(&nonce, &m[..10]);

    {
        let take =
            if c.len() % 16 == 0 { (c.len() / 16 - 2) * 16 }
            else { (c.len() / 16 - 1) * 16 };

        let (input, input_remaining) = c.split_at(take);
        let (output, output_remaining) = p.split_at_mut(take);

        for (input, output) in input.chunks(BLOCK_LENGTH)
            .zip(output.chunks_mut(BLOCK_LENGTH))
        {
            let input = array_ref!(input, 0, BLOCK_LENGTH);
            let output = array_mut_ref!(output, 0, BLOCK_LENGTH);
            process.process(input, output);
        }
        let r = process.finalize(input_remaining, output_remaining);
        assert!(r);
    }

    assert_eq!(&p[..], &m[..]);


    // decrypt 2
    let mut p2 = vec![0; m2.len()];
    let mut process = cipher.decrypt(&nonce, &m[..16]);

    {
        let take =
            if c2.len() % 16 == 0 { (c2.len() / 16 - 2) * 16 }
            else { (c2.len() / 16 - 1) * 16 };

        let (input, input_remaining) = c2.split_at(take);
        let (output, output_remaining) = p2.split_at_mut(take);

        for (input, output) in input.chunks(BLOCK_LENGTH)
            .zip(output.chunks_mut(BLOCK_LENGTH))
        {
            let input = array_ref!(input, 0, BLOCK_LENGTH);
            let output = array_mut_ref!(output, 0, BLOCK_LENGTH);
            process.process(input, output);
        }
        let r = process.finalize(input_remaining, output_remaining);
        assert!(r);
    }

    assert_eq!(&p2[..], &m2[..]);
}
