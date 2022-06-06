#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include <stdlib.h>
#include <string.h>

#include "gadget.h"
#include "LIEF/MachO/Binary.h"

#define HOOK_SIZE 0x20

extern void hexdump(char *desc, void *addr, int len);

void
gadget_relocate_call(gadget_insn_t *insns, void *fct_start_ptr, gadget_flags_t flags);

void
gadget_do_asm(const char *inst, void **current_ptr, unsigned char **encode, size_t *encoded_size, size_t *count);

csh cs_handle = -1;
ks_engine *ks;

mapped_function_t mapped_functions[1000];
int mapped_functions_count = 0;

trampoline_jmp_t *trampoline_jmp;
int trampoline_jmp_count = 0;

void *gadget_jmp_ptr = NULL;
void* gadget_start_ptr;

int gadget_print_function(csh handle, void *ptr, int offset) {

    int length = 0;
    int ret = 0;
    int count = 0;
    
    int total_count = 0;

    while (length < 0x1000 && ret == 0) {
        cs_insn *insn;
        count = cs_disasm(handle, ptr + length, 0x24, ((uint64_t)ptr+length),1 , &insn);
        total_count = total_count + count;
        if (count > 0) {
            length = length + insn->size;

            for (int j = 0; j < count; j++) {
                for (int k = 0 ; k < offset ; k++) {
                    printf(" ");
                }
			    printf("0x%"PRIx64":\t%s\t\t%s\t\t\t;", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);

                for (int k = 0 ; k < insn[j].size; k++) {
                    printf("%02X ", insn[j].bytes[k]);
                }     

                printf("\n");

                if (strcmp(insn[j].mnemonic,"retq") == 0) {
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

int gadget_get_function(csh handle, void *ptr, int offset) {

    int length = 0;
    int ret = 0;
    int count = 0;

    int total_count = 0;

    while (length < 0x1000 && ret == 0) {
        cs_insn *insn;
        count = cs_disasm(handle, ptr + length, 0x24, ((uint64_t)ptr+length),1 , &insn);
        total_count = total_count + count;
        if (count > 0) {
            length = length + insn->size;

            for (int j = 0; j < count; j++) {

                if (strcmp(insn[j].mnemonic,"retq") == 0) {
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

    
    }

    insns->bytes_length += total_count;
    return insns;
}

void gadget_relocate_instruction(cs_insn * insn, cs_insn *next_insn, void *dest_ptr) {

    uint64_t dest_address;

    char *line = strdup(insn->op_str); 

    char *lop = strtok(line, ","); 
    char *rop = strtok(NULL, ",");  

    if( lop != NULL  && rop != NULL) {

        if (strstr(lop, "(%rip)") != NULL) {

            uint64_t orig_offset;

            sscanf(lop, " 0x%llX(%%rip)", &orig_offset);

            dest_address = next_insn->address + orig_offset;

            printf("found lop rip relative pointer at 0x%llx, relocating to 0x%llx \n", orig_offset, dest_address);
            strcpy(insn->mnemonic, "movabsq");
            sprintf(insn->op_str, "$0x%llx, %%r10", dest_address);

            strcpy(next_insn->mnemonic, "leaq");
            sprintf(next_insn->op_str, "(%%r10), %s", rop);
            
        }

        if (strstr(rop,"(%rip)") != NULL) {
            uint64_t orig_offset;

            sscanf(rop, " 0x%llx(%%rip)", &orig_offset);

            dest_address = next_insn->address + orig_offset;

            printf("found rop rip relative pointer at 0x%llx, relocating to 0x%llx \n", orig_offset, dest_address);
            strcpy(insn->mnemonic, "movabsq");
            sprintf(insn->op_str, "$0x%llx, %%r10", dest_address);

            strcpy(next_insn->mnemonic, "leaq");
            sprintf(next_insn->op_str, "(%%r10), %s", lop);

        }
    }
}



void gadget_dump_function() {
    printf("here \n");

    static int nb_call=0;

    //if (nb_call == 0) {
        asm("callq *%0" ::"r" (mapped_functions[nb_call*2+1].jmp_ptr));
    //}

    nb_call++;
}

void* gadget_assemble(gadget_insn_t *insns, void *dest_ptr, int do_gadget) {
    void *current_ptr = dest_ptr;
    char instruction[200];
    unsigned char* encode;
    size_t encoded_size;
    size_t count;

    for (int i = 0 ; i < insns->count; i++) {

        sprintf(instruction, "%s %s", insns->instructions[i].mnemonic, insns->instructions[i].op_str);

        if (ks_asm(ks, instruction, ((uint64_t)current_ptr), &encode, &encoded_size, &count) != KS_ERR_OK) {
            printf("Failed to encode instruction \n");
            exit(-1);
        } else {
            memcpy(current_ptr, encode, encoded_size);
            current_ptr += encoded_size;
            ks_free(encode);
        }

    }

    uint64_t aligned_addr = ((((uint64_t)current_ptr / 2) + 1) * 2);

    return (void*) aligned_addr;
}

void
gadget_do_asm(const char *inst, void **current_ptr, unsigned char **encode, size_t *encoded_size,
              size_t *count) {
    if (ks_asm(ks, inst, ((uint64_t) (*current_ptr)), encode, encoded_size, count) != 0) {
        printf("Failed to encode instruction %s : %d \n", inst, ks_errno(ks));
        exit(-1);
    } else {
        memcpy((*current_ptr), (*encode), (*encoded_size));
        (*current_ptr) += (*encoded_size);     ks_free((*encode));
    }
}

void* gadget_relocate_const(gadget_insn_t* insns, void * dest_ptr)
{

    unsigned char* encode;
    size_t encoded_size;
    size_t count;

    char instruction[200];

    void *current_ptr = dest_ptr;

    for (int i = 0 ; i < insns->count; i+=2) {

        //gadget_relocate_instruction(&insns->instructions[i], &insns->instructions[i+1], current_ptr);

        for (int offset = 0 ; offset <= 1; offset ++) {
            int index = i + offset;
            sprintf(instruction, "%s %s", insns->instructions[index].mnemonic, insns->instructions[index].op_str);

            printf("Processing instruction %s \n", instruction);

            if (ks_asm(ks, instruction, ((uint64_t) current_ptr), &encode, &encoded_size, &count) != KS_ERR_OK) {
                printf("Failed to encode instruction %d \n", ks_errno(ks));
            } else {
                current_ptr += encoded_size;
                ks_free(encode);
            }
        }


    }

    
    //uint64_t aligned_addr = ((((uint64_t)current_ptr / 16) + 1) * 16);

    return (void*) current_ptr;
}


void gadget_relocate_calls(const char* fct_name, void *fct_source_addr, void* fct_dest_addr, gadget_flags_t flags) {

    // decompile function
    int total_count;
    int offset = (2 - flags.recursion_levels)  * 2;
    gadget_insn_t insns;

    printf("do_gadget on %s relocate to %p \n", fct_name, fct_dest_addr);

    total_count = gadget_get_function(cs_handle, fct_source_addr, offset);

    gadget_get_instructions(cs_handle, total_count, fct_source_addr, &insns);

    if (flags.recursion_levels > 0) {
        gadget_relocate_call(&insns, fct_dest_addr, flags);
    }

    gadget_print_function(cs_handle, fct_dest_addr, offset);
}

void gadget_relocate_call(gadget_insn_t *insns, void *dest_fct_ptr, gadget_flags_t flags) {

    void *dest_memory_ptr = dest_fct_ptr;
    uint64_t relocate_offset = (uint64_t) (dest_fct_ptr - insns->instructions[0].address);

    for (int i = 0; i < insns->count; i++) {
        if (strcmp(insns->instructions[i].mnemonic, "callq") == 0) {

            uint64_t addr;
            bool mapped = false;
            bool trampolined = false;
            sscanf(insns->instructions[i].op_str,"0x%llx",&addr);
            for ( int j = 0 ; j < mapped_functions_count ; j++) {
                if (mapped_functions[j].source_ptr  == (void*)addr || mapped_functions[j].gadget_ptr == (void*)addr || mapped_functions[j].dest_ptr == (void*) addr) {
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
                mapped_functions[mapped_functions_count].dest_ptr = dest_fct_ptr;
                mapped_functions[mapped_functions_count].jmp_ptr = dest_fct_ptr;
                mapped_functions[mapped_functions_count].gadget_ptr = gadget_start_ptr + (HOOK_SIZE * (mapped_functions_count));
                
                sprintf(insns->instructions[i].op_str,"0x%llx",(uint64_t)mapped_functions[mapped_functions_count].gadget_ptr);

                char inst[200];

                sprintf(inst, "callq %s ", insns->instructions[i].op_str);
                //gadget_do_asm(inst, insns->instructions[i].address)

                unsigned char *encode;
                size_t encoded_size;
                size_t count;
                if (ks_asm(ks, inst, (uint64_t)dest_memory_ptr, &encode, &encoded_size, &count) != 0) {
                    printf("Failed to encode instruction %s : %d \n", inst, ks_errno(ks));
                    exit(-1);
                } else {
                    printf("encoded %ld\n", encoded_size);
                    memcpy((void *) dest_memory_ptr, encode, encoded_size);
                    ks_free(encode);
                }

                mapped_functions_count ++;
                char new_function_name[200];

                sprintf(new_function_name, "0x%llx", addr);

                gadget_flags_t next_level;
                next_level.recursion_levels = flags.recursion_levels - 1;
                next_level.execute = 0;

                gadget_relocate_calls(new_function_name, addr, addr+relocate_offset, next_level);
            }
        }

        dest_memory_ptr += insns->instructions[i].size;
    }

}

void gadget_create_hooks() {

    for (int i = 0 ; i < mapped_functions_count; i++) {
        gadget_create_hook(mapped_functions[i].gadget_ptr, i);
    }
}


void test() {
    gadget_dump_function();
}

void gadget_create_hook(void *start_address, int functionnr) {
    char inst[200];

    void *current_ptr = start_address;

    unsigned char *encode;
    size_t encoded_size;
    size_t count = 0;


    gadget_do_asm("pushq %rbp", &current_ptr, &encode, &encoded_size, &count);

    gadget_do_asm("movq    %rsp, %rbp", &current_ptr, &encode, &encoded_size, &count);


    sprintf(inst, "callq %p", gadget_dump_function);
    gadget_do_asm(inst, &current_ptr, &encode, &encoded_size, &count);

    gadget_do_asm("popq %rbp", &current_ptr, &encode, &encoded_size, &count);

    gadget_do_asm("retq", &current_ptr, &encode, &encoded_size, &count);

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
    }

    // find nb of imports
    trampoline_jmp = malloc(sizeof(struct trampoline_jmp_struct) * trampoline_jmp_count);

    for (int j = 0 ; j < trampoline_jmp_count ; j ++) {
        trampoline_jmp[j].addr = base_address + trampoline_offset + (j*6);
        trampoline_jmp[j].number = j;
    }

    // find the
    for (int i = 0 ; binary->segments[i] != NULL; i++) {
        printf("%s \n", binary->segments[i]->name);
    }

    macho_binaries_destroy(binaries);

}

void gadget_init(uint64_t base_address, void *gadget_start_addr) {

    gadget_get_imports(base_address);

    gadget_start_ptr = gadget_start_addr;

    cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle);
    cs_option(cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    ks_open(KS_ARCH_X86,  KS_MODE_64, &ks);
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);

}