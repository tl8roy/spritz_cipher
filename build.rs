fn main() {
    cc::Build::new()
        //.file("c_examples/SpritzCipher.c")
        .file("c_examples/spritz.c")
        .compile("SpritzCipher");
}