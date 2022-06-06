use std::{fs, process};
use std::fmt::{Display, Formatter};
use std::path::Path;
use goblin::mach;
use proc_maps::{get_process_maps, MapRange, Pid};
use memory_bytes::MemoryBytes;

#[derive(Copy, Clone)]
pub struct ExecutableSection {

    base_address: usize,

    size: usize,

    main_address: usize,

    exec_name: &'static str,

    section_memory: MemoryBytes,

}

impl Display for ExecutableSection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "base_address: 0x{:x}, main_address: 0x{:x}, size:  0x{:x}, exec_name: {}",
               self.base_address,
               self.main_address,
               self.size,
               self.exec_name)
    }
}

impl ExecutableSection {

    pub fn new(path: &'static Path) -> Result<ExecutableSection, String> {

        let file_name = path.file_name().expect("Failed to get filename").to_str().unwrap();
        let i = get_base_address(String::from(file_name)).expect("Failed to get base address");
        let j = get_function_address(i.start(), "main", path).expect("Failed to find main address");
        let k = MemoryBytes::new(i.start(), i.size()).expect("Failed to read source memory");

        return Ok(ExecutableSection{
            base_address: i.start(),
            size: i.size(),
            main_address: j,
            exec_name: file_name,
            section_memory: k
        });
    }

    pub fn main_address(&self) -> usize{
        return self.main_address;
    }

    pub fn base_address(&self) -> usize{
        return self.base_address;
    }

    pub fn size(&self) -> usize {
        return self.size;
    }

    pub fn exec_name(&self) -> String {
        return self.exec_name.to_string();
    }

    pub fn section_memory(self) -> MemoryBytes { return self.section_memory; }

}

fn get_base_address(exec_name: String) -> Result<MapRange, String> {

    let pid = process::id();
    let maps = get_process_maps(pid as Pid);

    for map in maps.unwrap() {

        if map.filename().is_some() && map.filename().unwrap().to_str().unwrap().ends_with(exec_name.as_str()) && map.is_exec() {
            return Ok(map);
        }

    }
    return Err(String::from("Base address not found"));
}

fn get_function_address(base_address: usize, fct_name: &str, path: &Path) -> Result<usize, String>
{

    let buffer = fs::read(path);

    if buffer.is_ok() {
        let buffer = buffer.unwrap();
        let parse_result = mach::Mach::parse(&buffer);
        if parse_result.is_ok()
        {
            match parse_result.unwrap() {
                mach::Mach::Binary(bin) => {
                    let exports = bin.exports().unwrap();

                    for exp_vect in exports.iter() {
                        if exp_vect.name.contains(fct_name) {
                            return Ok(exp_vect.offset as usize + base_address);
                        }
                    }
                }
                _ => {
                    return Err(String::from("Not a macho file"));
                }
            }
        }
    }
    return Err(String::from("Failed to read file"));


}