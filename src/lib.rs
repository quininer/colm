extern crate core;

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

        // Generate the Masks
        self.0.encrypt(&mut l);
        let mut l3 = Block::default();
        mult!(x3; &mut l3, &l);
        mult!(inv2; &mut delta0, &l3);
        let delta1 = l;
        mult!(x3; &mut delta2, &l3);

        // Process Associated Data
        let mut blk = Block::default();

        // make the first block blk based on npub and param
        blk[..NONCE_LENGTH].copy_from_slice(nonce);

        iter::once(&blk[..])
            .chain(aad.chunks(BC::BLOCK_LENGTH))
            .for_each(|next| {
                // Process the current Block
                let mut xx = Block::default();
                if next.len() < 16 {
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
            _mode: E
        }
    }
}

pub struct Process0<'a, BC: BlockCipher + 'a, Mode> {
    cipher: &'a BC,
    delta1: Block,
    delta2: Block,
    w: Block,
    _mode: Mode
}

impl<'a, BC : BlockCipher + 'a> Process0<'a, BC, E> {
    pub fn process(&mut self, buf: &mut [u8]) {
        // TODO
    }

    pub fn tag(self, tag: &mut [u8; BLOCK_LENGTH]) {
        //
    }
}
