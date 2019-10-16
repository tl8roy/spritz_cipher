//! # Spritz Cipher
//! 
//! `spritz_cipher` is a Rust implementation of the Spritz Cipher.
//! 
//! ```Spritz - a spongy RC4-like stream cipher and hash function.```
//! 
//! Spritz is an improvement on RC4 based upon this [paper](https://people.csail.mit.edu/rivest/pubs/RS14.pdf)
//!
//! The tests and examples have Encryption, Hash and MAC implementations. It requires no dependencies when used as a library.
//! The tests and examples use rand and libc to compare against 2 different C implementations.
//! 
//! 
//! # Limitations
//! Spritz is not as robust as other ciphers. There are known theortical attacks that may or may not allow an attacker to comprise the communication.
//! Spritz is also slower than SHA3.
//! That said, it is better than nothing

#![no_std]

const SPRITZ_N: usize = 256;
const SPRITZ_N_MINUS_1: usize = SPRITZ_N - 1;
const SPRITZ_N_HALF: usize = SPRITZ_N / 2;

use zeroize::Zeroize;
#[derive(Debug)]
pub enum SpritzCipherError {
    LengthsDontMatch,
}

/// The primary structure that contains the buffer and varirables for the Cipher
// This struct will be zeroized on drop
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SpritzCipherContext {
    //s-box
    s: [u8; SPRITZ_N],
    i: u8,
    j: u8,
    k: u8,
    z: u8,
    a: u8,
    w: u8,
    
    tmp1: u8,
    tmp2: u8,

}

impl SpritzCipherContext {
    fn init() -> SpritzCipherContext {

        let mut context = SpritzCipherContext {
            //s-box
            s: [0;SPRITZ_N],
            i: 0,
            j: 0,
            k: 0,
            z: 0,
            a: 0,
            w: 1,

            tmp1: 0,
            tmp2: 0,

        };

        for (key,val) in context.s.iter_mut().enumerate(){
            *val = key as u8;
        }

        context
    }

    fn state_s_swap(&mut self, index_a: u8, index_b: u8)
    {
        self.tmp1       = self.s[index_a as usize];
        self.s[index_a as usize] = self.s[index_b as usize];
        self.s[index_b as usize] = self.tmp1;
    }

    fn update(&mut self)
    {
        self.i = self.i.wrapping_add(self.w);
        self.j = self.s[(self.s[self.i as usize].wrapping_add(self.j)) as usize].wrapping_add(self.k);
        self.k = self.s[self.j as usize].wrapping_add(self.k).wrapping_add(self.i);
        self.state_s_swap(self.i, self.j);
    }

    fn whip(&mut self)
    {
        for _i in 0..SPRITZ_N_HALF {
            self.update();
            self.update();
            self.update();
            self.update();
        }

        self.w = self.w + 2;
    }

    #[inline(never)]
    #[no_builtins]
    #[cold]
    //__attribute__ ((optnone))
    fn crush(&mut self){
        let mut j = SPRITZ_N_MINUS_1;
        for i in 0..SPRITZ_N_HALF {
            self.tmp1 = self.s[i]; /* s_i=self.s[i] */
            self.tmp2 = self.s[j]; /* s_j=self.s[j] */
            if self.tmp1 > self.tmp2 { /* if(s_i>s_j) */
                self.s[i] = self.tmp2; /* self.s[i]=s_j */
                self.s[j] = self.tmp1; /* self.s[j]=s_i */
            }
            else {
                self.s[i] = self.tmp1; /* self.s[i]=s_i */
                self.s[j] = self.tmp2; /* self.s[j]=s_j */
            }
            j -= 1;
        }
    }

    fn shuffle(&mut self)
    {
        self.whip();
        self.crush();
        self.whip();
        self.crush();
        self.whip();
        self.a = 0;
    }

    fn absorb_nibble(&mut self, nibble: u8)
    {
        if self.a == SPRITZ_N_HALF as u8 {
            self.shuffle();
        }
        self.state_s_swap(self.a, SPRITZ_N_HALF as u8 + nibble);
        self.a += 1;
    }

    fn absorb(&mut self, octet: u8)
    {
        self.absorb_nibble(octet % 16); /* With the Right/Low nibble */
        self.absorb_nibble(octet / 16); /* With the Left/High nibble */
    }

    fn absorb_bytes(&mut self, buf: &[u8])
    {
        //for byte in 0..buf.len {
        for byte in buf.iter() {
            self.absorb(*byte);
        }
    }

    fn absorb_stop(&mut self)
    {
        if self.a == SPRITZ_N_HALF as u8 {
            self.shuffle();
        }

        self.a += 1;
    }

    //Types are screwed up here probably
    fn output(&mut self) -> u8
    {
        self.z = self.s[
                    (self.s[
                        (self.s[
                            (self.z.wrapping_add(self.k)) as usize % SPRITZ_N
                        ] as usize + self.i as usize) % SPRITZ_N as usize
                    ] as usize + self.j as usize) % SPRITZ_N
                ];
        return self.z;
    }


    fn drip(&mut self) -> u8
    {
        if self.a > 0 {
            self.shuffle();
        }
        self.update();
        return self.output();
    }


    
    /// Timing-safe equality comparison for `data_a` and `data_b`.
    /// 
    /// This function can be used to compare the password's hash safely.
    /// * Parameter data_a: Data a to be compare with b.
    /// * Parameter data_b: Data b to be compare with a.
    ///
    /// Return: Equality result.
    /// * Zero (0x00) if `data_a` equals `data_b`,
    /// * Non-zero value if they are NOT equal.
    /// * Error if the array lengths don't match
    /// * Probably should be replaced by a bool (Thoughts?)
    ///
    /// # Examples
    ///
    /// ```
    /// use spritz_cipher::SpritzCipherContext;
    /// const BUFFER_SIZE: usize = 24;
    /// let mut msg: [u8;BUFFER_SIZE] = ['A' as u8;BUFFER_SIZE];
    /// let mut buf: [u8;BUFFER_SIZE] = [ 65 as u8;BUFFER_SIZE];
    ///
    /// assert_eq!(SpritzCipherContext::compare(&buf, &msg).unwrap(), 0);
    /// buf[0] =  buf[0].wrapping_add(1);
    /// assert_ne!(SpritzCipherContext::compare(&buf, &msg).unwrap(),0);
    /// ```
    /// 
    #[inline(never)]
    #[no_builtins]
    #[cold]
    pub fn compare(data_a: &[u8], data_b: &[u8]) -> Result<u8,SpritzCipherError>
    {
        if data_a.len() != data_b.len() {
            return Err(SpritzCipherError::LengthsDontMatch);
        }

        let mut d = 0;

        for i in 0..data_a.len() {
            d |= data_a[i] ^ data_b[i];
        }


        /* It may be possible to use `d=!!d;` for performnce,
        * But audit the assembly code first.
        */
        d |= d >> 1; /* |_|_|_|_|_|_|S|D| `D |= S` */
        d |= d >> 2; /* |_|_|_|_|_|S|_|D| */
        d |= d >> 3; /* |_|_|_|_|S|_|_|D| */
        d |= d >> 4; /* |_|_|_|S|_|_|_|D| */
        d |= d >> 5; /* |_|_|S|_|_|_|_|D| */
        d |= d >> 6; /* |_|S|_|_|_|_|_|D| */
        d |= d >> 7; /* |S|_|_|_|_|_|_|D| */
        d &= 1;      /* |0|0|0|0|0|0|0|D| Zero all bits except LSB */
        

        Ok(d)
    }


    /// Clear the spritz cipher context by placing 0 in all locations.
    /// 
    /// To be replaced by Zeroize once I get it working.
    /*#[inline(never)]
    #[no_builtins]
    #[cold]
    pub fn state_memzero(&mut self)
    {

        self.s = [0;SPRITZ_N];

        self.i = 0;
        self.j = 0;
        self.k = 0;
        self.z = 0;
        self.a = 0;
        self.w = 0;

        self.tmp1 = 0;
        self.tmp2 = 0;

    }*/
   

    /// Setup the context with a key.
    /// * Parameter key:    The key.
    /// 
    /// * Return: A Context setup and ready to use.
    pub fn setup(key: &[u8]) -> SpritzCipherContext
    {
        let mut context = SpritzCipherContext::init();
        context.absorb_bytes(key);
        if context.a > 0 {
            context.shuffle();
        }
        context
    }   

    /// Setup the context with a key and nonce/salt/iv.
    /// * Parameter key:      The key.
    /// * Parameter nonce:    The nonce (salt).
    /// 
    /// * Return: A Context setup and ready to use.
    #[allow(non_snake_case)]
    pub fn setup_with_IV(key: &[u8], nonce: &[u8]) -> SpritzCipherContext
    {
        let mut context = SpritzCipherContext::init();
        context.absorb_bytes(key);
        context.absorb_stop();
        context.absorb_bytes(nonce);
        if context.a > 0 {
            context.shuffle();
        }
        context
    }

    /// Generates a random byte from the spritz context.
    /// 
    /// Probably shouldn't use this unless you need too
    pub fn random8(&mut self) -> u8
    {
        self.drip()
    }

    /// Generates four random bytes from the spritz context.
    /// 
    /// Probably shouldn't use this unless you need too
    pub fn random32(&mut self) -> u32
    {
        (
        ((self.random8() as u32) <<  0)
        | ((self.random8() as u32) <<  8)
        | ((self.random8() as u32) << 16)
        | ((self.random8() as u32) << 24))
    }

    //// Calculate an uniformly distributed random number less than `upper_bound` avoiding modulo bias.
    ///
    /// Uniformity is achieved by generating new random numbers until the one
    /// returned is outside the range [0, 2**32 % upper_bound).
    /// 
    /// This guarantees the selected random number will be inside
    /// [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
    /// after reduction modulo upper_bound.
    /// 
    /// random32_uniform() derives from OpenBSD's arc4random_uniform()
    ///
    /// * Parameter upper_bound: The roof, `upper_bound - 1` is the largest number that can be returned.
    ///
    /// * Return: Random number less than upper_bound, 0 if upper_bound<2.
    /// 
    /// Probably shouldn't use this unless you need too
    pub fn random32_uniform(&mut self, upper_bound: u32) -> u32
    {

        if upper_bound < 2 {
            return 0;
        }

        /* 2**32 % x == (2**32 - x) % x */
        let min = (0-upper_bound) % upper_bound;

        /* This could theoretically loop forever but each retry has
        * p > 0.5 (worst case, usually far better) of selecting a
        * number inside the range we need, so it should rarely need
        * to re-roll.
        */
        loop {
            let r = self.random32();
            if r >= min {
                return r % upper_bound;
            }
        }
    }

    /// Add entropy to the spritz context using absorb().
    /// * Parameter entropy: The entropy array.
    pub fn add_entropy(&mut self, entropy: &[u8])
    {
        self.absorb_bytes(entropy);
    }

    /// Encrypt or decrypt data chunk by XOR-ing it with the spritz keystream.
    /// 
    /// * Parameter data:    The data to encrypt or decrypt.
    /// * Parameter data_out: The output.
    /// 
    /// Returns an error if the array lengths don't match
    /// ```
    ///    use spritz_cipher::SpritzCipherContext;
    /// 
    ///    const BUFFER_SIZE: usize = 24;
    ///    const KEY_SIZE: usize = 32;
    /// 
    ///     use rand::prelude::*;
    ///     
    /// 
    ///     /* Data to input */
    ///     let mut msg: [u8;BUFFER_SIZE] = ['A' as u8;BUFFER_SIZE];
    ///     let mut key = [0u8;KEY_SIZE];
    ///     thread_rng().fill(&mut key);
    ///     thread_rng().fill(&mut msg);
    /// 
    ///     let mut buf = [0 as u8;BUFFER_SIZE]; /* Output buffer */
    ///     
    ///     //Encrypt
    ///     let mut context = SpritzCipherContext::setup(&key);
    ///     context.crypt(&msg, &mut buf);
    /// 
    ///     //Decrypt
    ///     let mut context = SpritzCipherContext::setup(&key);
    ///     let buf2 = buf.clone();
    ///     context.crypt(&buf2, &mut buf);
    /// 
    ///     /* Check the output */
    ///     assert_eq!(SpritzCipherContext::compare(&buf, &msg).unwrap(), 0);
    ///  ```
    pub fn crypt(&mut self, data: &[u8], data_out: &mut [u8]) -> Result<(),SpritzCipherError>
    {

        if data.len() != data_out.len() {
            return Err(SpritzCipherError::LengthsDontMatch);
        }

        for (i,byte) in data.iter().enumerate() {
            data_out[i] = byte ^ self.drip();
        }

        Ok(())
    }


    /// Setup the spritz hash context.
    /// * Return: A Context setup and ready to use.
    pub fn hash_setup() -> SpritzCipherContext {
        SpritzCipherContext::init()
    }

    /// Add a message/data chunk `data` to hash.
    /// * Parameter data:     The data chunk to hash.
    pub fn hash_update(&mut self, data: &[u8]) {
        self.absorb_bytes(data);
    }

    /// Output the hash digest.
    /// * Parameter digest:    The digest (hash) output.
    pub fn hash_final(&mut self, digest: &mut [u8])
    {

        self.absorb_stop();
        self.absorb(digest.len() as u8);
        /* squeeze() */
        if self.a > 0 {
            self.shuffle();
        }

        for byte in digest.iter_mut() {
            *byte = self.drip();
        }
    }

    //// Cryptographic hash function.
    /// * Parameter digest:    The digest (hash) output.
    /// * Parameter data:      The data to hash.
    /// ```
    /// use spritz_cipher::SpritzCipherContext;
    /// 
    ///    const BUFFER_SIZE: usize = 32;
    ///
    ///    let test_vector: [u8; BUFFER_SIZE] =
    ///    [ 0xff, 0x8c, 0xf2, 0x68, 0x09, 0x4c, 0x87, 0xb9,
    ///    0x5f, 0x74, 0xce, 0x6f, 0xee, 0x9d, 0x30, 0x03,
    ///    0xa5, 0xf9, 0xfe, 0x69, 0x44, 0x65, 0x3c, 0xd5,
    ///    0x0e, 0x66, 0xbf, 0x18, 0x9c, 0x63, 0xf6, 0x99
    ///    ];
    ///    let test_data: [u8; 7] = [ 'a' as u8, 'r' as u8, 'c' as u8, 'f' as u8, 'o' as u8, 'u' as u8, 'r' as u8 ];
    ///
    ///    let mut digest = [0u8;BUFFER_SIZE]; /* Output buffer */
    ///    let mut digest_2 = [0u8;BUFFER_SIZE]; /* Output buffer for chunk by chunk API */
    /// 
    ///    let mut context = SpritzCipherContext::hash_setup();
    ///    /* For easy test: code add a byte each time */
    ///    for byte in test_data.iter() {
    ///        context.hash_update(&[*byte]);
    ///    }
    ///    context.hash_final(&mut digest_2);
    /// 
    ///    //Short cut the above steps by doing it all in one hit
    ///    SpritzCipherContext::hash(&mut digest, &test_data);
    /// 
    ///    /* Check the output */
    ///    assert_eq!(SpritzCipherContext::compare(&digest, &test_vector).unwrap(), 0);
    /// 
    ///    assert_eq!(SpritzCipherContext::compare(&digest_2, &test_vector).unwrap(), 0);
    /// ```
    pub fn hash(digest: &mut [u8], data: &[u8])
    {

        let mut context = SpritzCipherContext::hash_setup(); /* spritz_state_init() */
        context.hash_update(data); /* absorbBytes() */
        context.hash_final(digest);

        //context.state_memzero();
        context.zeroize();
        
    }


    //// Setup the spritz message authentication code (MAC) context.
    /// * Parameter key:     The secret key.
    /// 
    /// * Return: A Context setup and ready to use.
    pub fn mac_setup(key : &[u8]) -> SpritzCipherContext
    {
        let mut context = SpritzCipherContext::hash_setup(); /* spritz_state_init() */
        context.hash_update(key); /* absorbBytes() */
        context.absorb_stop();
        context
    }

    //// Add a message/data chunk to message authentication code (MAC).
    /// * Parameter msg:      The message chunk to be authenticated.
    pub fn mac_update(&mut self, msg: &[u8])
    {
        self.hash_update(msg); /* absorbBytes() */
    }

    /// Output the message authentication code (MAC) digest.
    /// * Parameter digest:    Message authentication code (MAC) digest output.
    pub fn mac_final(&mut self, digest: &mut [u8])
    {
        self.hash_final(digest);
    }

    /// Message Authentication Code (MAC) function.
    /// * Parameter digest:    Message authentication code (MAC) digest output.
    /// * Parameter msg:       The message to be authenticated.
    /// * Parameter key:       The secret key.
    /// ```
    ///     /* Data to input */
    ///    let mut msg: [u8;3] = ['A' as u8, 'B' as u8, 'C' as u8];
    ///    let mut key: [u8;3] = [0x00, 0x01, 0x02];
    /// 
    ///    const BUFFER_SIZE: usize = 32;
    ///    let test_vector: [u8; BUFFER_SIZE] =
    ///    [ 0xbe, 0x8e, 0xdc, 0xf2, 0x76, 0xcf, 0x57, 0xb4,
    ///    0x0e, 0xbc, 0x8e, 0x22, 0x43, 0x45, 0x7e, 0x3e,
    ///    0xb7, 0xc6, 0x4d, 0x4e, 0x99, 0x1e, 0x93, 0x58,
    ///    0xce, 0x81, 0xef, 0xb1, 0x6c, 0xce, 0xc7, 0xed
    ///    ];
    ///  
    ///    let mut digest = [0u8;BUFFER_SIZE]; /* Output buffer */
    /// 
    ///    use spritz_cipher::SpritzCipherContext;
    ///    SpritzCipherContext::mac(&mut digest, &mut msg, &mut key);
    /// 
    ///    /* Check the output */
    ///    assert_eq!(SpritzCipherContext::compare(&digest, &test_vector).unwrap(), 0);
    /// ```
    pub fn mac(digest: &mut[u8], msg: &mut[u8], key: &mut[u8]) {

        let mut context = SpritzCipherContext::mac_setup(key);
        context.mac_update(msg); /* absorbBytes() */
        context.mac_final(digest);

        //context.state_memzero();
        context.zeroize();
        
    }


}
