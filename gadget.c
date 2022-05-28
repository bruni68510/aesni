#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include <stdlib.h>
#include <string.h>

#include "gadget.h"
#include "LIEF/MachO/Binary.h"

extern void hexdump(char *desc, void *addr, int len);

void *gadget_relocate_call(gadget_insn_t *insns, void *start_ptr, gadget_flags_t flags);

csh cs_handle = -1;
mapped_function_t mapped_functions[1000];
int mapped_functions_count = 0;

trampoline_jmp_t *trampoline_jmp;
int trampoline_jmp_count = 0;


int gadget_print_function(csh handle, void *ptr) {

    int length = 0;
    int ret = 0;
    int count = 0;
    
    int total_count = 0;

    while (length < 0x1000 && ret == 0) {
        cs_insn *insn;
        count = cs_disasm(handle, ptr + length, 0x24, ((uint64_t)ptr+length),1 , &insn);
        total_count += count;
        if (count > 0) {
            length = length + insn->size;

            for (int j = 0; j < count; j++) {
			    printf("0x%"PRIx64":\t%s\t\t%s\t\t\t;", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);

                for (int k = 0 ; k < insn[j].size; k++) {
                    printf("%02X ", insn[j].bytes[k]);
                }     

                printf("\n");

                if (strcmp(insn[j].mnemonic,"ret") == 0) {
                    ret = 1;
                }
		    }
        }
        else {
            break;
        }
    
    }
    return total_count;
}

gadget_insn_t* gadget_get_instructions(csh handle, int total_count, void * ptr, gadget_insn_t* insns ) {


    insns->instructions = malloc((sizeof (cs_insn)) * total_count);
    insns->bytes_length = 0;
    insns->count = total_count;

    for ( int j = 0 ; j < total_count; j++) {

        cs_insn *insn;
        cs_disasm(handle, ptr + insns->bytes_length, 0x24, ((uint64_t)ptr+insns->bytes_length),1 , &insn);
        insns->bytes_length += insn->size;

        insns->instructions[j].address = insn->address;
        strcpy(insns->instructions[j].mnemonic, insn->mnemonic);
        strcpy(insns->instructions[j].op_str, insn->op_str);
        insns->instructions[j].size = insn->size;
        

        cs_free(insn, insn->size);
    
    }

    return insns;
}


void gadget_relocate_instruction(cs_insn * insn, void *dest_ptr) {

    int64_t dest_offset; 

    char *line = strdup(insn->op_str); 

    char *lop = strtok(line, ","); 
    char *rop = strtok(NULL, ",");  

    if( lop != NULL  && rop != NULL) {

        if (strstr(rop, "[rip +") != NULL) {

            int64_t orig_offset;

            sscanf(rop, " [rip + 0x%llx]", &orig_offset);   

            dest_offset = (insn->address - (uint64_t) dest_ptr) + orig_offset;
            
            if (dest_offset >= 0) {
                printf("found rip relative pointer at 0x%llx, relocating to 0x%llx \n", orig_offset, dest_offset);
            }
            else
            {
                //dest_offset -= 22;
                //printf("found rip relative pointer at 0x%llx, relocating to -0x%llx \n", orig_offset, -dest_offset);

                sprintf(insn->op_str, "%s, [rip - 0x%llx", lop, -dest_offset);
            }
            
        }

    }
}

void* gadget_assemble(gadget_insn_t *insns, void *dest_ptr) {
    void *current_ptr = dest_ptr;
    char instruction[200];
    unsigned char* encode;
    size_t encoded_size;
    size_t count;

    ks_engine *ks;

    ks_err err = ks_open(KS_ARCH_X86,  KS_MODE_64, &ks);

    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        exit(-1);
    }

    for (int i = 0 ; i < insns->count; i++) {

        sprintf(instruction, "%s %s", insns->instructions[i].mnemonic, insns->instructions[i].op_str);

        if (ks_asm(ks, instruction, ((uint64_t)current_ptr), &encode, &encoded_size, &count) != KS_ERR_OK) {
            printf("Failed to encode instruction \n");
        } else {
            memcpy(current_ptr, encode, encoded_size);
            current_ptr += encoded_size;
            ks_free(encode);
        }
    }

    if (ks != NULL) {
        ks_close(ks);
    }

    uint64_t aligned_addr = ((((uint64_t)current_ptr / 16) + 1) * 16);

    return (void*) aligned_addr;
}

void* gadget_relocate_const(gadget_insn_t* insns, void * dest_ptr)
{

    unsigned char* encode;
    size_t encoded_size;
    size_t count;

    char instruction[200];

    void *current_ptr = dest_ptr;

    ks_engine *ks;

    ks_err err = ks_open(KS_ARCH_X86,  KS_MODE_64, &ks);

    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        exit(-1);
    }

    for (int i = 0 ; i < insns->count; i++) {

        gadget_relocate_instruction(&(insns->instructions[i]), current_ptr);

        sprintf(instruction, "%s %s", insns->instructions[i].mnemonic, insns->instructions[i].op_str);

        //printf("Processing instruction %s \n", instruction);

        if (ks_asm(ks, instruction, ((uint64_t)current_ptr), &encode, &encoded_size, &count) != KS_ERR_OK) {
            printf("Failed to encode instruction \n");
        } else {

            current_ptr += encoded_size;
            ks_free(encode);
        }
    }

    if (ks != NULL) {
        ks_close(ks);
    }
    
    uint64_t aligned_addr = ((((uint64_t)current_ptr / 16) + 1) * 16);

    return (void*) aligned_addr;
}

void gadget_execute(void *addr) {
    
    int (*main_ptr) (int argc, char**) = (int (*) (int argc, char**)) addr;

    printf("calling new mail at %p\n", main_ptr);

    main_ptr(0, NULL);
}


void* do_gadget(const char* fct_name, void *ptr, void *dest_addr, gadget_flags_t flags) {

    // decompile function
    int total_count;

    gadget_insn_t insns;
    gadget_flags_t next_level;

    next_level.execute = false;
    next_level.recursion_levels = flags.recursion_levels - 1;

    printf("do_gadget on %s relocate to %p \n", fct_name, dest_addr);

    total_count = gadget_print_function(cs_handle, ptr);

    gadget_get_instructions(cs_handle, total_count, ptr, &insns);

    void *next_ptr = gadget_relocate_const(&insns, dest_addr);

    if (next_level.recursion_levels > 0) {
        void *second_next_ptr = next_ptr;
        do {
            next_ptr = second_next_ptr;
            second_next_ptr = gadget_relocate_call(&insns, second_next_ptr, next_level);
        } while (second_next_ptr != next_ptr);
    }

    gadget_assemble(&insns, dest_addr);

    gadget_print_function(cs_handle, dest_addr);


    if (flags.execute) {
        gadget_execute(dest_addr);
    }



    return next_ptr;
}

void *gadget_relocate_call(gadget_insn_t *insns, void *start_ptr, gadget_flags_t flags) {

    for (int i = 0; i < insns->count; i++) {
        if (strcmp(insns->instructions[i].mnemonic, "call") == 0) {
            uint64_t addr;
            bool mapped = false;
            bool trampolined = false;
            sscanf(insns->instructions[i].op_str,"0x%llx",&addr);
            for ( int j = 0 ; j < mapped_functions_count ; j++) {
                if (mapped_functions[j].source_ptr == (void*)addr || mapped_functions[j].dest_ptr == (void*) addr) {
                    mapped = true;
                    break;
                }
            }

            for (int j = 0 ; j < trampoline_jmp_count ; j++) {
                if (trampoline_jmp[j].addr == addr) {
                    trampolined = true;
                }
            }

            if (!mapped && !trampolined) {
                mapped_functions[mapped_functions_count].source_ptr = (void*)addr;
                mapped_functions[mapped_functions_count].dest_ptr = start_ptr;
                mapped_functions_count ++;
                return do_gadget(insns->instructions[i].op_str, (void*) addr, start_ptr, flags)  ;
            }

        }
    }

}

void gadget_get_imports(uint64_t base_address)
{
    Macho_Binary_t ** binaries = macho_parse("./aesni");

    Macho_Binary_t *binary = (*binaries);
    trampoline_jmp_count = 0;
    uint64_t trampoline_offset = 0;
    // find trampoline base addr
    for (int i = 0 ; binary->sections[i] != NULL; i++) {
        if (strcmp(binary->sections[i]->name, "__stubs") == 0) {
            trampoline_offset = binary->sections[i]->offset;
            trampoline_jmp_count = binary->sections[i]->size / 6;
        }
        printf("%s \n", binary->sections[i]->name);
    }

    // find nb of imports
    trampoline_jmp = malloc(sizeof(struct trampoline_jmp_struct) * trampoline_jmp_count);

    for (int j = 0 ; j < trampoline_jmp_count ; j ++) {
        trampoline_jmp[j].addr = base_address + trampoline_offset + (j*6);
        trampoline_jmp[j].number = j;
    }

    macho_binaries_destroy(binaries);

}

void gadget_init(uint64_t base_address) {

    gadget_get_imports(base_address);

    cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle);


}