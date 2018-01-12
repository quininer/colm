use ::traits::{ BLOCK_LENGTH, BlockCipher };
use ::{ Block, Process0, E, D };


macro_rules! xor {
    ( $res:expr, $s:expr ) => {
        for i in 0..BLOCK_LENGTH {
            $res[i] ^= $s[i];
        }
    };
    ( $res:expr, $x:expr, $y:expr ) => {
        for i in 0..BLOCK_LENGTH {
            $res[i] = $x[i] ^ $y[i];
        }
    };
}

macro_rules! mult {
    ( x2 ; $res:expr, $s:expr ) => {
        let t = $s[0] >> 7;
        for i in 0..15 {
            $res[i] = ($s[i] << 1) | ($s[i + 1] >> 7);
        }
        $res[15] = $s[15] << 1;
        if t == 1 {
            $res[15] ^= 0x87;
        }
    };
    ( inv2 ; $res:expr, $s:expr ) => {
        let t = $s[15] & 1;
        for i in 1..16 {
            $res[i] = ($s[i - 1] << 7) | ($s[i] >> 1);
        }
        $res[0] = $s[0] >> 1;
        if t == 1 {
            $res[15] ^= 0x43;
            $res[0] ^= 0x80;
        }
    };

    ( x3 ; $res:expr, $s:expr ) => {
        let mut res = Block::default();
        mult!(x2; &mut res, $s);
        xor!($res, &res, $s);
    };

    ( x7 ; $res:expr, $s:expr ) => {
        let mut res = Block::default();
        mult!(x2; &mut res, $s);
        mult!(x3; &mut res, &res);
        xor!($res, &res, $s);
    }
}

pub fn p(w: &mut Block, y: &mut Block, x: &Block) {
    let (mut w2, mut w3) = (Block::default(), Block::default());
    mult!(x3; &mut w3, w);
    mult!(x2; &mut w2, w);
    xor!(y, x, w3);
    xor!(w, x, w2);
}

pub fn p_inv(w: &mut Block, y: &mut Block, x: &Block) {
    let mut w3 = Block::default();
    mult!(x3; &mut w3, w);
    xor!(y, x, w3);
    xor!(w, x, w);
}

pub trait Mask {
    fn mask(delta: &mut Block, xx: &mut Block, input: &Block);
}

pub mod state {
    use ::{ Block, BLOCK_LENGTH };
    use super::Mask;

    pub struct Process;
    pub struct LastFul;
    pub struct Last;
    pub type Tag = Process;

    impl Mask for Process {
        #[inline]
        fn mask(delta: &mut Block, xx: &mut Block, input: &Block) {
            mult!(x2; delta, delta);
            xor!(xx, input, delta);
        }
    }

    impl Mask for LastFul {
        #[inline]
        fn mask(delta: &mut Block, xx: &mut Block, input: &Block) {
            mult!(x7; delta, delta);
            xor!(xx, input, delta);
        }
    }

    impl Mask for Last {
        #[inline]
        fn mask(delta: &mut Block, xx: &mut Block, input: &Block) {
            mult!(x7; delta, delta);
            mult!(x7; delta, delta);
            xor!(xx, input, delta);
        }
    }
}


impl<'a, BC : BlockCipher + 'a> Process0<'a, BC, E> {
    pub(crate) fn process_block<State: Mask>(&mut self, input: &Block, output: &mut Block) {
        let (mut xx, mut yy) = Default::default();

        // Mask
        State::mask(&mut self.delta1, &mut xx, input);

        // Encrypt
        self.cipher.encrypt(&mut xx);

        // Linear Mixing
        p(&mut self.w, &mut yy, &xx);

        // Encrypt
        self.cipher.encrypt(&mut yy);

        // Mask
        State::mask(&mut self.delta2, output, &yy);
    }
}

impl<'a, BC : BlockCipher + 'a> Process0<'a, BC, D> {
    pub(crate) fn process_block<State: Mask>(&mut self, input: &Block, output: &mut Block) {
        let (mut xx, mut yy) = Default::default();

        // Mask
        State::mask(&mut self.delta2, &mut xx, input);

        // Encrypt
        self.cipher.decrypt(&mut xx);

        // Linear Mixing
        p_inv(&mut self.w, &mut yy, &xx);

        // Encrypt
        self.cipher.decrypt(&mut yy);

        // Mask
        State::mask(&mut self.delta1, output, &yy);
    }
}
