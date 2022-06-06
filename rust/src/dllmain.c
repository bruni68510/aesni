//
// Created by Christophe Brunner on 01.06.22.
//

#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>

void (*do_start) (void);

__attribute__((constructor)) void DllMain() {

    printf("starting dll main \n");
    void* handle = dlopen("./libwidevine_gadget.dylib", RTLD_NOW);

    if (handle == NULL ){
        printf("dlopen failed \n");
    }
    else {
        do_start = dlsym(handle, "do_start");

        do_start();

        exit(0);
    }

}
