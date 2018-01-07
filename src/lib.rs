#![feature(nll)]

extern crate core;
#[macro_use] extern crate arrayref;
extern crate subtle;

#[macro_use] mod module;
pub mod traits;

use core::iter;
use subtle::slices_equal;
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

    pub fn decrypt<'a>(&'a self, nonce: &[u8; NONCE_LENGTH], aad: &[u8]) -> Process0<'a, BC, D> {
        let (delta1, delta2, w) = self.init(nonce, aad);

        Process0 {
            cipher: &self.0,
            delta1, delta2, w,
            cs: Block::default(),
            _mode: D
        }
    }
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
    pub fn process<'b, I, O>(&mut self, input: I, output: O)
        where
            I: Iterator<Item = &'b [u8; BLOCK_LENGTH]>,
            O: Iterator<Item = &'b mut [u8; BLOCK_LENGTH]>
    {
        for (input, output) in input.zip(output) {
            xor!(&mut self.cs, input);
            self.process_block(State::Process, input, output);
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
            if len < BC::BLOCK_LENGTH {
                buf[len] = 0x80;
                State::Last
            } else { State::LastFul };

        xor!(&mut buf, &self.cs);
        self.process_block(state, &buf, output);

        // Process checksum block
        let mut tmp = Block::default();
        self.process_block(State::Tag, &buf, &mut tmp);
        tag.copy_from_slice(&tmp[..tag.len()]);
    }
}


impl<'a, BC : BlockCipher + 'a> Process0<'a, BC, D> {
    pub fn process<'b, I, O>(&mut self, input: I, output: O)
        where
            I: Iterator<Item = &'b [u8; BLOCK_LENGTH]>,
            O: Iterator<Item = &'b mut [u8; BLOCK_LENGTH]>
    {
        for (input, output) in input.zip(output) {
            self.process_block(State::Process, input, output);
            xor!(&mut self.cs, output);
        }
    }

    pub fn finalize(mut self, input: &[u8], output: &mut [u8]) -> bool {
        const OZS: [u8; 16] = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];

        assert!(!input.is_empty());
        assert!(input.len() > BC::BLOCK_LENGTH && input.len() <= 2 * BC::BLOCK_LENGTH);
        assert_eq!(input.len(), output.len() + BC::BLOCK_LENGTH);

        let len = input.len() - BC::BLOCK_LENGTH;
        let mut buf = Block::default();
        let (input, tag) = input.split_at(BC::BLOCK_LENGTH);
        let input = array_ref!(input, 0, BLOCK_LENGTH);

        let state =
            if len < BC::BLOCK_LENGTH { State::Last }
            else { State::LastFul };

        self.process_block(state, input, &mut buf);
        xor!(&mut self.cs, &buf);
        let (val, remaining) = self.cs.split_at(tag.len());
        output.copy_from_slice(val);

        let r = slices_equal(remaining, &OZS[..remaining.len()]);


        // Process checksum block
        let Process0 { cipher, delta1, delta2, w, cs, .. } = self;
        let mut process = Process0 { cipher, delta1, delta2, w, cs, _mode: E };

        let mut tmp = Block::default();
        process.process_block(State::Tag, &buf, &mut tmp);
        let r2 = slices_equal(tag, &tmp[..tag.len()]);

        r == 1 && r2 == 1
    }
}
