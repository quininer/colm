#![feature(nll)]

extern crate core;
#[macro_use] extern crate arrayref;

#[macro_use] mod module;
pub mod traits;

use core::iter;
use traits::{ KEY_LENGTH, BLOCK_LENGTH };
use traits::BlockCipher;
use module::*;


pub struct Colm<BC: BlockCipher>(BC);
pub struct E;
pub struct D;
pub type Block = [u8; BLOCK_LENGTH];
pub const NONCE_LENGTH: usize = 8;

impl<BC: BlockCipher> Colm<BC> {
    pub fn new(key: &[u8; KEY_LENGTH]) -> Self {
        Colm(BC::new(key))
    }

    fn init(&self, nonce: &[u8; NONCE_LENGTH], aad: &[u8]) -> (Block, Block, Block) {
        let mut w = Block::default();
        let mut l = Block::default();
        let mut delta0 = Block::default();
        let mut delta2 = Block::default();
        let delta1;

        // Generate the Masks
        self.0.encrypt(&mut l);
        let mut l3 = Block::default();
        mult!(x3; &mut l3, &l);
        mult!(inv2; &mut delta0, &l3);
        delta1 = l;
        mult!(x3; &mut delta2, &l3);

        // Process Associated Data
        let mut nonce_block = Block::default();
        // make the first block blk based on npub and param
        nonce_block[..NONCE_LENGTH].copy_from_slice(nonce);
        nonce_block[NONCE_LENGTH] = 0x80;

        iter::once(&nonce_block[..])
            .chain(aad.chunks(BC::BLOCK_LENGTH))
            .for_each(|next| {
                // Process the current Block
                let mut xx = Block::default();
                if next.len() < BC::BLOCK_LENGTH {
                    mult!(x7; delta0, delta0);
                } else {
                    mult!(x2; delta0, delta0);
                }
                xor!(xx, next, delta0);
                self.0.encrypt(&mut xx);
                xor!(w, xx);
            });

        (delta1, delta2, w)
    }

    pub fn encrypt<'a>(&'a self, nonce: &[u8; NONCE_LENGTH], aad: &[u8]) -> Process0<'a, BC, E> {
        let (delta1, delta2, w) = self.init(nonce, aad);

        Process0 {
            cipher: &self.0,
            delta1, delta2, w,
            buf: Block::default(),
            _mode: E
        }
    }
}

pub struct Process0<'a, BC: BlockCipher + 'a, Mode> {
    cipher: &'a BC,
    delta1: Block,
    delta2: Block,
    w: Block,
    buf: Block,
    _mode: Mode
}

impl<'a, BC : BlockCipher + 'a> Process0<'a, BC, E> {
    fn process_buf(&mut self, block: &mut Block) {
        let mut xx = Block::default();

        // Mask
        mult!(x2; self.delta1, self.delta1);
        xor!(xx, self.buf, self.delta1);

        // Encrypt
        self.cipher.encrypt(&mut xx);

        // Linear Mixing
        p(&mut self.w, block, &xx);

        // Encrypt
        self.cipher.encrypt(block);

        // Mask
        mult!(x2; self.delta2, self.delta2);
        xor!(block, self.delta2);
    }

    pub fn process<'b>(&mut self, input: &'b [u8], output: &mut [u8]) -> Result<(), &'b [u8]> {
        assert_eq!(input.len(), output.len());

        for (input, output) in input.chunks(BC::BLOCK_LENGTH)
            .zip(output.chunks_mut(BC::BLOCK_LENGTH))
        {
            if input.len() < BC::BLOCK_LENGTH {
                return Err(input);
            }

            let input = array_ref!(input, 0, BLOCK_LENGTH);
            let output = array_mut_ref!(output, 0, BLOCK_LENGTH);
            self.buf.clone_from(input);
            self.process_buf(output);
        }

        Ok(())
    }

    pub fn finalize(mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() < BC::BLOCK_LENGTH);
        assert_eq!(input.len() + BC::BLOCK_LENGTH, output.len());

        let (buf, remaining) = output.split_at_mut(BC::BLOCK_LENGTH);

        if !input.is_empty() {
            let len = input.len();
            let buf = array_mut_ref!(buf, 0, BLOCK_LENGTH);

            buf[..len].copy_from_slice(input);
            buf[len] = 0x80;
            for b in &mut buf[len..] {
                *b = 0x00;
            }

            self.buf.clone_from(buf);
            self.process_buf(buf);
        }

        let mut tmp = Block::default();

        mult!(x3; tmp, self.delta1);
        xor!(self.delta1, tmp);
        mult!(x3; tmp, self.delta2);
        xor!(self.delta2, tmp);

        self.process_buf(&mut tmp);
        remaining.copy_from_slice(&tmp[..remaining.len()]);
    }
}
