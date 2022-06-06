use std::convert::TryInto;
use libc::{c_ulonglong, c_void};

#[derive(Copy, Clone)]
pub struct MemoryBytes {
    address: usize,

    size: usize
}

impl MemoryBytes {

    pub fn new(address: usize, size: usize) -> Result<MemoryBytes, String> {

        Ok(MemoryBytes{
            address: address,
            size: size
        })
    }

    pub fn read_bytes(&self) -> Vec<u8> {
        unsafe { return self.unsafe_read_bytes().unwrap() };
    }

    unsafe fn unsafe_read_bytes(self) -> Result<Vec<u8>, String> {

        let mem = libc::malloc(self.size);
        let mut bytes = Vec::new();

        println!("Read bytes from address 0x{:x} for size 0x{:x}", self.address, self.size);

        libc::memcpy(mem,addr_to_ptr(self.address as c_ulonglong ), self.size  );

        for i in 0..self.size-1 {
            bytes.push(ptr_byte_value_at(mem, i.try_into().unwrap()));
        }

        libc::free(mem);

        Ok(bytes)
    }
}

extern {
    fn addr_to_ptr(input: libc::c_ulonglong) -> * const c_void;
}

extern {
    fn ptr_byte_value_at(ptr: * const libc::c_void, offset: libc::c_int) -> libc::c_uchar;
}


