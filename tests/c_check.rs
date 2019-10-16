#[cfg(test)]
mod c_check {
    #[test]
    fn compare_arduino() {

        use spritz_cipher::SpritzCipherContext;
        use rand::prelude::*;
        use libc::size_t;

        extern  {
            /*fn spritz_mac(digest: *mut u8, digestLen: size_t,
                            msg: *const u8, msgLen: size_t,
                            key: *const u8, keyLen: size_t);*/
            fn spritz_auth(digest: *mut u8, digestLen: size_t,
                            msg: *const u8, msgLen: size_t,
                            key: *const u8, keyLen: size_t);
        }

        

        let mut check = Vec::new();
        check.extend_from_slice(&mut [0f64;256]);

        //loop {
            const BUFFER_SIZE: usize = 512;
            const KEY_SIZE: usize = 128;
            const DIGEST_SIZE: usize = 32;
    
            /* Data to input */
            let mut msg: [u8;BUFFER_SIZE] = ['A' as u8;BUFFER_SIZE];
            let mut key = [0u8;KEY_SIZE];
            thread_rng().fill(&mut key);
            thread_rng().fill(&mut msg);

            let mut mac_1 = [0 as u8;DIGEST_SIZE]; /* Output buffer */
            let mut mac_2 = [0 as u8;DIGEST_SIZE]; /* Output buffer */
            let mut mac_3 = [0 as u8;DIGEST_SIZE]; /* Output buffer */

            SpritzCipherContext::mac(&mut mac_1, &mut msg, &mut key);

            unsafe {
                //spritz_mac(mac_2.as_mut_ptr(),mac_2.len() as size_t,msg.as_ptr(),msg.len() as size_t,key.as_ptr(),key.len() as size_t);
                spritz_auth(mac_3.as_mut_ptr(),mac_3.len() as size_t,msg.as_ptr(),msg.len() as size_t,key.as_ptr(),key.len() as size_t);
            }

            /*print!("Key: ");
            for val in key.iter(){
                print!("{:X}",val);
            }
            println!("");
            println!("");

            print!("Input: ");
            for val in msg.iter(){
                print!("{:X}",val);
            }
            println!("");
            println!("");*/

            print!("MAC 1: ");
            for val in mac_1.iter(){
                print!("{:X}",val);
            }
            println!("");

            print!("MAC 2: ");
            for val in mac_3.iter(){
                print!("{:X}",val);
            }
            println!("");
            println!("");

            /* Check the output */
            //assert_eq!(SpritzCipherContext::compare(&mac_1, &mac_2), 0);
            assert_eq!(SpritzCipherContext::compare(&mac_1, &mac_3).unwrap(), 0);
            

            mac_1[0] =  mac_1[0].wrapping_add(1);
            //assert_ne!(SpritzCipherContext::compare(&mac_1, &mac_2),0);
            assert_ne!(SpritzCipherContext::compare(&mac_1, &mac_3).unwrap(),0);



        //}
    }
}