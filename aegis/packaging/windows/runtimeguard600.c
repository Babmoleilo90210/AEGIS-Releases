#include "runtimeguard600.h"
/* Loaded and retained by NSIS throughout replacement; Windows closes locks on crash. */
__declspec(dllexport) HANDLE __cdecl acquire(int exclusive){return aegis_runtime_guard600(exclusive!=0);}
__declspec(dllexport) void __cdecl release(HANDLE handle){aegis_runtime_release600(handle);}
