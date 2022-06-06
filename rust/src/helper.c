//
// Created by Christophe Brunner on 05.06.22.
//

void* addr_to_ptr(unsigned long long addr) {
    return (void *) addr;
}

unsigned char ptr_byte_value_at(void *ptr, int offset) {

    unsigned char* char_ptr = (unsigned char*) ptr;

    return char_ptr[offset];
}