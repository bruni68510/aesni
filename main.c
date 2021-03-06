#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdlib.h>

#include <capstone/capstone.h>

#include "gadget.h"

vm_offset_t main_offset = 0x3ed0;

vm_address_t base_addr;
vm_address_t new_section_addr;

vm_address_t get_base_address()
{
    kern_return_t kern_return;
    mach_port_t task;

   int pid = getpid();

   // Need to run this program as root (i.e. sudo) in order for this to work
   kern_return = task_for_pid(mach_task_self(), pid, &task);
   if (kern_return != KERN_SUCCESS)
   {
      printf("task_for_pid() failed, error %d - %s\n", kern_return, mach_error_string(kern_return));
        return 0;
   }

   kern_return_t kret;
   vm_region_basic_info_data_t info;
   mach_vm_size_t size;
   mach_port_t object_name;
   mach_msg_type_number_t count;
   vm_address_t firstRegionBegin;
   vm_address_t lastRegionEnd;
   vm_size_t fullSize;
   count = VM_REGION_BASIC_INFO_COUNT_64;
   mach_vm_address_t address = 1;
   int regionCount = 0;
   int flag = 0;
   while (flag == 0)
   {
      //Attempts to get the region info for given task
      kret = mach_vm_region(task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t) &info, &count, &object_name);
      if (kret == KERN_SUCCESS)
      {
         if (regionCount == 0)
         {
            firstRegionBegin = address;
            regionCount += 1;
         }
         fullSize += size;
         address += size;
      }
      else
         flag = 1;
   }
   lastRegionEnd = address;
   printf("Base Address: %p\n",(void*)firstRegionBegin);

   return firstRegionBegin;

}


void* map_memory(const char* name, int size) {
    void *map = mmap(NULL, 0x10000, PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0 );

    if (map == NULL ){
        printf("mmap failed");
        exit(-1);
    } else {
        printf("memory mapped at %p\n", map);
    }

    return map;
}


__attribute__((constructor)) void DllMain() {
    /*
    gadget_flags_t flags;

    flags.recursion_levels = 2;
    flags.execute = 1;

    int (*main_ptr) (int argc, char**); 

    base_addr = get_base_address();
    main_ptr = (void*) (base_addr+main_offset);
    printf("main ptr at %p \n", main_ptr);

    void *fct_section_ptr = map_memory("function memory", 0x10000);
    void *gadget_section_ptr = map_memory("function memory", 0x10000);

    memcpy(fct_section_ptr, (void*) base_addr, 0x9000);

    gadget_init(base_addr, gadget_section_ptr);

    gadget_relocate_calls("main", main_ptr, fct_section_ptr+main_offset, flags);

    gadget_create_hooks();

    main_ptr = fct_section_ptr+main_offset ;

    //asm( "callq *%0" :: "r" (fct_section_ptr+main_offset));

    main_ptr(0, NULL);

    exit(0);
    */
}