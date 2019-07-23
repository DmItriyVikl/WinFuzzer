// Fuzzer.h : Include file for standard system include files,
// or project specific include files.

#pragma once
#include "windows.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
class Fuzz {
private:
    BOOL crproc;
    PROCESS_INFORMATION pi;
    DEBUG_EVENT dbg;
    HANDLE thread;
    CONTEXT context;
    BOOL exception;
    HANDLE process;
    DWORD wait_timeA;
    STARTUPINFO cif;
    char inputA[];
public:
    bool launcher(char* path, char input[], DWORD wait_time);
    char inputGenerator();
    int Observer();

};


// TODO: Reference additional headers your program requires here.
