pub const KEY_LENGTH: usize = 16;
pub const BLOCK_LENGTH: usize = 16;


pub trait BlockCipher {
    const KEY_LENGTH: usize;
    const BLOCK_LENGTH: usize;

    fn new(key: &[u8; KEY_LENGTH]) -> Self;
    fn encrypt(&self, block: &mut [u8; BLOCK_LENGTH]);
    fn decrypt(&self, block: &mut [u8; BLOCK_LENGTH]);
}
