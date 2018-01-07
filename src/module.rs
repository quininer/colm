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

macro_rules! mask {
    ( $state:expr; $delta:expr, $xx:expr, $input:expr ) => {
        match $state {
            State::Process | State::Tag => {
                mult!(x2; $delta, $delta);
                xor!($xx, $input, $delta);
            },
            State::LastFul => {
                mult!(x7; $delta, $delta);
                xor!($xx, $input, $delta);
            },
            State::Last => {
                mult!(x7; $delta, $delta);
                mult!(x7; $delta, $delta);
                xor!($xx, $input, $delta);
            }
        }
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

pub enum State {
    Process,
    LastFul,
    Last,
    Tag
}

impl<'a, BC : BlockCipher + 'a> Process0<'a, BC, E> {
    pub(crate) fn process_block(&mut self, state: State, input: &Block, output: &mut Block) {
        let mut xx = Block::default();

        // Mask
        mask!(state; self.delta1, xx, input);

        // Encrypt
        self.cipher.encrypt(&mut xx);

        // Linear Mixing
        p(&mut self.w, output, &xx);

        // Encrypt
        self.cipher.encrypt(output);

        // Mask
        mask!(state; self.delta2, output, output);
    }
}

impl<'a, BC : BlockCipher + 'a> Process0<'a, BC, D> {
    pub(crate) fn process_block(&mut self, state: State, input: &Block, output: &mut Block) {
        let mut xx = Block::default();

        // Mask
        mask!(state; self.delta2, xx, input);

        // Encrypt
        self.cipher.decrypt(&mut xx);

        // Linear Mixing
        p_inv(&mut self.w, output, &xx);

        // Encrypt
        self.cipher.decrypt(output);

        // Mask
        mask!(state; self.delta1, output, output);
    }
}
