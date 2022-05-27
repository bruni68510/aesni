#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <stdlib.h>
#include <string.h>

extern void hexdump(char *desc, void *addr, int len);


csh cs_handle = -1;

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

void* gadget_relocate(gadget_insn_t* insns, void * dest_ptr)
{
    ks_engine *ks = NULL;
    ks_err err;
    int offset = 0;

    unsigned char* encode;
    size_t encoded_size;
    size_t count;
   
    int64_t dest_offset;
    char instruction[200];

    void *current_ptr = dest_ptr;

    err = ks_open(KS_ARCH_X86,  KS_MODE_64, &ks);

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

            /*
            printf("instr encoded:");

            for (int j = 0; j < encoded_size; j++) {
              printf("%02x ", encode[j]);
            }

            printf("\n");
            */

            if (memcpy(current_ptr, encode, encoded_size) == NULL) {
                perror("failed to write memory");
            }

            

            current_ptr += encoded_size;
        
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


void do_gadget(const char* fct_name, void *ptr, void *dest_addr, gadget_flags_t flags) {

    // decompile function
    int total_count;

    gadget_insn_t ori_fct;

    printf("do_gadget on %s \n", fct_name);

    total_count = gadget_print_function(cs_handle, ptr);

    gadget_get_instructions(cs_handle, total_count, ptr, &ori_fct);

    gadget_relocate(&ori_fct, dest_addr);

    if (flags.execute) {
        gadget_execute(dest_addr);
    }

}

void gadget_init() {
    cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle);
}