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

void gadget_init();
void do_gadget(const char* fct_name, void *ptr, void *dest_addr, gadget_flags_t flags);

#endif