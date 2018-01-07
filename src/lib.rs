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

        iter::once(&nonce_block[..])
            .chain(aad.chunks(BC::BLOCK_LENGTH))
            .for_each(|next| {
                // Process the current Block
                let len = next.len();
                let mut xx = Block::default();

                xx[..len].copy_from_slice(next);
                if len < BC::BLOCK_LENGTH {
                    xx[len] = 0x80;
                    mult!(x7; &mut delta0, &delta0);
                } else {
                    mult!(x2; &mut delta0, &delta0);
                }
                xor!(xx, delta0);
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
            cs: Block::default(),
            _mode: E
        }
    }

    /*
    pub fn auth(&self, nonce: &[u8; NONCE_LENGTH], aad: &[u8], output: &mut [u8; BLOCK_LENGTH]) {
        let mut process = self.encrypt(nonce, aad);
        let mut buf = Block::default();
        buf[0] = 0x80;
        Process0::process_block(&mut process, State::Last, &buf, output);
    }
    */
}

pub struct Process0<'a, BC: BlockCipher + 'a, Mode> {
    cipher: &'a BC,
    delta1: Block,
    delta2: Block,
    w: Block,
    cs: Block,
    _mode: Mode
}

impl<'a, BC : BlockCipher + 'a> Process0<'a, BC, E> {
    pub fn process2<'b, I, O>(&mut self, input: I, output: O)
        where
            I: Iterator<Item = &'b [u8; BLOCK_LENGTH]>,
            O: Iterator<Item = &'b mut [u8; BLOCK_LENGTH]>
    {
        for (input, output) in input.zip(output) {
            for i in 0..BLOCK_LENGTH {
                self.cs[i] ^= input[i];
            }
            Self::process_block(self, State::Process, input, output);
        }
    }

    pub fn finalize(mut self, input: &[u8], output: &mut [u8]) {
        assert!(!input.is_empty());
        assert!(input.len() <= BC::BLOCK_LENGTH);
        assert_eq!(input.len() + BC::BLOCK_LENGTH, output.len());

        let len = input.len();
        let mut buf = Block::default();
        let (output, tag) = output.split_at_mut(BC::BLOCK_LENGTH);

        buf[..len].copy_from_slice(input);
        let output = array_mut_ref!(output, 0, BLOCK_LENGTH);

        let state =
            if len == BC::BLOCK_LENGTH { State::LastFul }
            else {
                buf[len] = 0x80;
                State::Last
            };

        for i in 0..BLOCK_LENGTH {
            buf[i] ^= self.cs[i];
        }
        Self::process_block(&mut self, state, &buf, output);

        // Process checksum block
        let mut tmp = Block::default();
        Self::process_block(&mut self, State::Tag, &buf, &mut tmp);
        tag.copy_from_slice(&tmp[..tag.len()]);
    }
}
