use ::traits::BLOCK_LENGTH;
use ::Block;


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
        mult!(x2; $res, $s);
        xor!($res, $s);
    };

    ( x7 ; $res:expr, $s:expr ) => {
        mult!(x2; $res, $s);
        mult!(x3; $res, $res);
        xor!($res, $s);
    }
}

pub fn p(w: &mut Block, y: &mut Block,  x: &Block) {
    let (mut w2, mut w3) = (Block::default(), Block::default());
    mult!(x3; &mut w3, w);
    mult!(x2; &mut w2, w);
    xor!(y, x, w3);
    xor!(w, x, w2);
}

pub fn inv_p(w: &mut Block, y: &mut Block,  x: &Block) {
    let mut w3 = Block::default();
    mult!(x3; &mut w3, w);
    xor!(y, x, w3);
    xor!(w, x, w);
}
