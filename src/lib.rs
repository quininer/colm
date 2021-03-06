#![no_std]
#![feature(nll)]
#![cfg_attr(feature = "cargo-clippy", allow(needless_range_loop, assign_op_pattern))]

#[macro_use] extern crate arrayref;
extern crate subtle;

#[macro_use] mod module;
pub mod traits;

use core::iter;
use subtle::ConstantTimeEq;
use traits::{ KEY_LENGTH, BLOCK_LENGTH };
use traits::BlockCipher;
use module::*;


#[derive(Debug, Clone)]
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
        let mut l = [0; BLOCK_LENGTH];
        let mut delta0 = [0; BLOCK_LENGTH];
        let     delta1;
        let mut delta2 = [0; BLOCK_LENGTH];

        // Generate the Masks
        self.0.encrypt(&mut l);
        let mut l3 = [0; BLOCK_LENGTH];
        mult!(x3; &mut l3, &l);
        mult!(inv2; &mut delta0, &l3);
        delta1 = l;
        mult!(x3; &mut delta2, &l3);

        // Process Associated Data
        let mut nonce_block = [0; BLOCK_LENGTH];
        // make the first block blk based on npub and param
        nonce_block[..NONCE_LENGTH].copy_from_slice(nonce);

        let w = iter::once(&nonce_block[..])
            .chain(aad.chunks(BC::BLOCK_LENGTH))
            .fold([0; BLOCK_LENGTH], |mut sum, next| {
                // Process the current Block
                let len = next.len();
                let mut xx = [0; BLOCK_LENGTH];

                xx[..len].copy_from_slice(next);
                if len < BC::BLOCK_LENGTH {
                    xx[len] = 0x80;
                    mult!(x7; &mut delta0, &delta0);
                } else {
                    mult!(x2; &mut delta0, &delta0);
                }
                xor!(xx, delta0);
                self.0.encrypt(&mut xx);
                xor!(sum, xx);

                sum
            });

        (delta1, delta2, w)
    }

    pub fn encrypt<'a>(&'a self, nonce: &[u8; NONCE_LENGTH], aad: &[u8]) -> Process0<'a, BC, E> {
        let (delta1, delta2, w) = self.init(nonce, aad);

        Process0 {
            cipher: &self.0,
            delta1, delta2, w,
            cs: [0; BLOCK_LENGTH],
            _mode: E
        }
    }

    pub fn decrypt<'a>(&'a self, nonce: &[u8; NONCE_LENGTH], aad: &[u8]) -> Process0<'a, BC, D> {
        let (delta1, delta2, w) = self.init(nonce, aad);

        Process0 {
            cipher: &self.0,
            delta1, delta2, w,
            cs: [0; BLOCK_LENGTH],
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
    pub fn process(&mut self, input: &Block, output: &mut Block) {
        xor!(&mut self.cs, input);
        self.process_block::<state::Process>(input, output);
    }

    pub fn finalize(mut self, input: &[u8], output: &mut [u8]) {
        assert!(!input.is_empty()); // XXX should be allow input is empty?
        assert!(input.len() <= BC::BLOCK_LENGTH);
        assert_eq!(input.len() + BC::BLOCK_LENGTH, output.len());

        let len = input.len();
        let mut buf = [0; BLOCK_LENGTH];
        let (output, tag) = output.split_at_mut(BC::BLOCK_LENGTH);

        buf[..len].copy_from_slice(input);
        let output = array_mut_ref!(output, 0, BLOCK_LENGTH);

        xor!(&mut buf, &self.cs);
        if len < BC::BLOCK_LENGTH {
            buf[len] ^= 0x80;
            self.process_block::<state::Last>(&buf, output);
        } else {
            self.process_block::<state::LastFul>(&buf, output);
        }

        // Process checksum block
        let mut tmp = [0; BLOCK_LENGTH];
        self.process_block::<state::Tag>(&buf, &mut tmp);
        tag.copy_from_slice(&tmp[..tag.len()]);
    }
}


impl<'a, BC : BlockCipher + 'a> Process0<'a, BC, D> {
    pub fn process(&mut self, input: &Block, output: &mut Block) {
        self.process_block::<state::Process>(input, output);
        xor!(&mut self.cs, output);
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
        let mut buf = [0; BLOCK_LENGTH];
        let (input, tag) = input.split_at(BC::BLOCK_LENGTH);
        let input = array_ref!(input, 0, BLOCK_LENGTH);

        if len < BC::BLOCK_LENGTH {
            self.process_block::<state::Last>(input, &mut buf);
        } else {
            self.process_block::<state::LastFul>(input, &mut buf);
        }

        xor!(&mut self.cs, &buf);
        let (val, remaining) = self.cs.split_at(tag.len());
        output.copy_from_slice(val);

        let r = remaining.ct_eq(&OZS[..remaining.len()]);


        // Process checksum block
        let Process0 { cipher, delta1, delta2, w, cs, .. } = self;
        let mut process = Process0 { cipher, delta1, delta2, w, cs, _mode: E };

        let mut tmp = [0; BLOCK_LENGTH];
        process.process_block::<state::Tag>(&buf, &mut tmp);
        let r2 = tag.ct_eq(&tmp[..tag.len()]);

        (r & r2).unwrap_u8() == 1
    }
}
