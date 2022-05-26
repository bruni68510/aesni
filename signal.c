#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdlib.h>

#include <capstone/capstone.h>

vm_address_t base_addr;

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


extern void do_gadget(const char* fct_name, void *ptr);

__attribute__((constructor)) void DllMain() {
    

    vm_offset_t main_offset = 0x3f10;
    
    int (*main_ptr) (int argc, char**); 

    //signal(10, catch_function);

    base_addr = get_base_address();

    main_ptr = (void*) (base_addr+main_offset);

    printf("main ptr at %p \n", main_ptr);

    do_gadget("main", main_ptr);

    exit(0);

}