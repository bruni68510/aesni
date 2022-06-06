extern crate proc_maps;
extern crate goblin;
extern crate capstone;
extern crate read_process_memory;
extern crate hexdump;
extern crate libc;

use std::path::Path;
use executable_section::ExecutableSection;
use gadget_function::GadgetFunction;

mod gadget_function;
mod memory_bytes;
mod executable_section;

#[no_mangle]
pub fn do_start() {

    let exec = ExecutableSection::new(
        Path::new("/Users/cbrunner/temp/aesni/rust/target/debug/aesni"))
        .expect("Failed to parse executable");

    println!("{}", exec);

    let _gadget = GadgetFunction::new(exec)
        .expect("Failed to gadget function");

    println!("all done");
}
