

extern crate cc;

fn main() {
    cc::Build::new()
        .file("src/helper.c")
        .compile("libhelper.a");
}