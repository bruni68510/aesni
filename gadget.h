#ifndef __GADGET_H
#define __GADGET_H

struct gadget_insn_struct {
    int count;
    cs_insn *instructions;
    int bytes_length;
};

typedef struct gadget_insn_struct gadget_insn_t;

struct gadget_flags_struct {
    bool execute;
    int recursion_levels;
};

typedef struct gadget_flags_struct gadget_flags_t;

struct mapped_function_struct {
    void *source_ptr;
    void *dest_ptr;
    void *jmp_ptr;
    void *gadget_ptr;
};

typedef struct mapped_function_struct mapped_function_t;

struct trampoline_jmp_struct {
    uint64_t addr;
    int number;
};

typedef struct trampoline_jmp_struct trampoline_jmp_t;

void gadget_init(u_int64_t base_address, void* gadget_start_addr);
void gadget_create_hook(void *start_address, int functionnr) ;
void gadget_relocate_calls(const char* fct_name, void *ptr, void *fct_dest_addr, gadget_flags_t flags);
void gadget_create_hooks();

#endif