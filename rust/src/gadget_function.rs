use std::cmp;
use std::io::Read;
use capstone::{arch, Capstone};
use capstone::prelude::{BuildsCapstone, BuildsCapstoneSyntax};
use ExecutableSection;
use memory_bytes::MemoryBytes;

pub struct GadgetFunction {

    function_name: String,

    nb_bytes: usize,

}


impl GadgetFunction {

    pub fn new(section: ExecutableSection) -> Result<GadgetFunction, String> {

        let max = section.main_address() + section.size() - section.main_address();
        let nb_bytes = find_nb_bytes_in_function(
            section.section_memory(),
            section.base_address(),
            section.main_address(),
            max). expect("Failed to compute nb of bytes of main function");

        return Ok(GadgetFunction {
            nb_bytes: nb_bytes,
            function_name: section.exec_name().to_string(),
            //orig_insns: None,
            //dest_insn: None,
            //bytes: None,
        });

    }


}
fn find_nb_bytes_in_function(memory: MemoryBytes, base_address: usize, fct_address: usize, max: usize) -> Result<usize, String> {

    let mut nb_of_bytes = 0;
    let offset = fct_address - base_address;

    let capstone = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        //.detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let bytes = memory.read_bytes();

    let mut address = fct_address;

    while nb_of_bytes < max {

        let mut slice: Vec<u8> = Vec::new();

        for i in nb_of_bytes..cmp::min(nb_of_bytes+8, max) {
            //slice.push(bytes.get(nb_of_bytes).unwrap());

            let v= bytes.get(i+offset).expect("Failed to get byte");
            slice.push(*v);
        }

        //hexdump::hexdump(&slice);

        let disasm_result = capstone.disasm_count(&*slice, address as u64, 1);

        if disasm_result.is_ok() {
            let insns = disasm_result.expect("Failed to get instruction");
            nb_of_bytes += insns.first().expect("Failed to get instruction").bytes().len();

            address += nb_of_bytes;

            println!("{} {}", insns.first().unwrap(), insns.first().unwrap().bytes().len());

            if insns.first().unwrap().mnemonic().unwrap().contains("ret") {
                break;
            }
        } else {
            return Err(String::from("failed to disassemble instruction"));
        }
    }

    Ok(nb_of_bytes)

}