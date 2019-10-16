
#[cfg(test)]
mod basic_tests {
    #[test]
    fn crypt() {

        use spritz_cipher::SpritzCipherContext;

        const BUFFER_SIZE: usize = 24;
        const KEY_SIZE: usize = 32;

        use rand::prelude::*;
        

        /* Data to input */
        let mut msg: [u8;BUFFER_SIZE] = ['A' as u8;BUFFER_SIZE];
        let mut key = [0u8;KEY_SIZE];
        thread_rng().fill(&mut key);
        thread_rng().fill(&mut msg);

        let mut buf = [0 as u8;BUFFER_SIZE]; /* Output buffer */


        let mut context = SpritzCipherContext::setup(&key);
        context.crypt(&msg, &mut buf);


        let mut context = SpritzCipherContext::setup(&key);
        let buf2 = buf.clone();
        context.crypt(&buf2, &mut buf);

        print!("Key: ");
        for val in key.iter(){
            print!("{}, ",val);
        }
        println!("");

        print!("Input: ");
        for val in msg.iter(){
            print!("{}, ",val);
        }
        println!("");

        print!("Output: ");
        for val in buf2.iter(){
            print!("{}, ",val);
        }
        println!("");

        print!("Decrypt: ");
        for val in buf.iter(){
            print!("{}, ",val);
        }
        println!("");


        /* Check the output */
        assert_eq!(SpritzCipherContext::compare(&buf, &msg).unwrap(), 0);

        buf[0] =  buf[0].wrapping_add(1);
        assert_ne!(SpritzCipherContext::compare(&buf, &msg).unwrap(),0);

    }

    #[test]
    fn hash() {

        use spritz_cipher::SpritzCipherContext;

        const BUFFER_SIZE: usize = 32;

        let test_vector: [u8; BUFFER_SIZE] =
        [ 0xff, 0x8c, 0xf2, 0x68, 0x09, 0x4c, 0x87, 0xb9,
        0x5f, 0x74, 0xce, 0x6f, 0xee, 0x9d, 0x30, 0x03,
        0xa5, 0xf9, 0xfe, 0x69, 0x44, 0x65, 0x3c, 0xd5,
        0x0e, 0x66, 0xbf, 0x18, 0x9c, 0x63, 0xf6, 0x99
        ];
        let test_data: [u8; 7] = [ 'a' as u8, 'r' as u8, 'c' as u8, 'f' as u8, 'o' as u8, 'u' as u8, 'r' as u8 ];

        let mut digest = [0u8;BUFFER_SIZE]; /* Output buffer */
        let mut digest_2 = [0u8;BUFFER_SIZE]; /* Output buffer for chunk by chunk API */


        let mut context = SpritzCipherContext::hash_setup();
        /* For easy test: code add a byte each time */
        for byte in test_data.iter() {
            context.hash_update(&[*byte]);
        }
        context.hash_final(&mut digest_2);

        SpritzCipherContext::hash(&mut digest, &test_data);

        /* Check the output */
        assert_eq!(SpritzCipherContext::compare(&digest, &test_vector).unwrap(), 0);

        assert_eq!(SpritzCipherContext::compare(&digest_2, &test_vector).unwrap(), 0);

    }

    #[test]
    fn mac() {

        /* Data to input */
        let mut msg: [u8;3] = ['A' as u8, 'B' as u8, 'C' as u8];
        let mut key: [u8;3] = [0x00, 0x01, 0x02];

        /* Test vectors */
        /* MSG='ABC' KEY=0x00,0x01,0x02 MAC test vectors */
        const BUFFER_SIZE: usize = 32;
        let test_vector: [u8; BUFFER_SIZE] =
        [ 0xbe, 0x8e, 0xdc, 0xf2, 0x76, 0xcf, 0x57, 0xb4,
        0x0e, 0xbc, 0x8e, 0x22, 0x43, 0x45, 0x7e, 0x3e,
        0xb7, 0xc6, 0x4d, 0x4e, 0x99, 0x1e, 0x93, 0x58,
        0xce, 0x81, 0xef, 0xb1, 0x6c, 0xce, 0xc7, 0xed
        ];

 
        let mut digest = [0u8;BUFFER_SIZE]; /* Output buffer */

        use spritz_cipher::SpritzCipherContext;
        SpritzCipherContext::mac(&mut digest, &mut msg, &mut key);

        /* Check the output */
        assert_eq!(SpritzCipherContext::compare(&digest, &test_vector).unwrap(), 0);

    }
}