#include <capstone/capstone.h>
#include <stdlib.h>
#include <string.h>

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

cs_insn* gadget_get_instructions(csh handle, int total_count, void * ptr) {

    int length = 0;
    cs_insn *insn;

    cs_insn* insns = malloc((sizeof (cs_insn)) * total_count);
    for ( int j = 0 ; j < total_count; j++) {

        cs_disasm(handle, ptr + length, 0x24, ((uint64_t)ptr+length),1 , &insn);
        length = length + insn->size;

        insns[j].address = insn->address;
        strcpy(insns[j].mnemonic,insn->mnemonic);
    }

    return insns;
}

void do_gadget(const char* fct_name, void *ptr) {

    // decompile function
    csh handle;

    int total_count = 0;
    int length = 0;
    int j = 0;

    printf("do_gadget on %s \n", fct_name);

    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);

    total_count = gadget_print_function(handle, ptr);

    cs_insn* insns = gadget_get_instructions(handle, total_count, ptr);
    
    
}