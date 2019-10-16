


fn main() {

    
        use spritz_cipher::SpritzCipherContext;
        use rand::prelude::*;

        let mut check = Vec::new();
        check.extend_from_slice(&mut [0f64;256]);

        loop {
            const BUFFER_SIZE: usize = 512;
            const KEY_SIZE: usize = 512;
    
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

            for val in buf2.iter(){
                check[*val as usize] += 1.0;
            }

            /* Check the output */
            assert_eq!(SpritzCipherContext::compare(&buf, &msg).unwrap(), 0);

            buf[0] =  buf[0].wrapping_add(1);
            assert_ne!(SpritzCipherContext::compare(&buf, &msg).unwrap(),0);

            let mut digest = [0u8;BUFFER_SIZE]; /* Output buffer */
            SpritzCipherContext::mac(&mut digest, &mut msg, &mut key);

            for val in digest.iter(){
                check[*val as usize] += 1.0;
            }

            use statistical::{standard_deviation};
            let sum = check.iter().fold(0.0,|a, &b| a + b); 
            println!("{}",standard_deviation(&check,Some(sum/256.0))/(sum/256.0) * 100.0 );

        }

}