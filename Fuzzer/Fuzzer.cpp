// Fuzzer.cpp : Defines the entry point for the application.
//

#include "Fuzzer.h"
//#include "stdafx.h"
#include "windows.h"
//#include "iostream.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CString>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>
#include <iterator>
#include <iostream>
#include <ctime>
#include <random>
//#include <botan/hex.h>

using namespace std;

int main()
{
	Fuzz Test;
	Test.launcher("C:\\Users\\ADMIN\\source\\repos\\Json_Parser\\Json_Parser\\out\\build\\x64-Debug\\Project.exe", " C:\\Users\\ADMIN\\source\\repos\\Fuzzer\\out\\build\\x64-Debug\\Fuzzer\\out.txt",1000);
	// 1 arg  exe file which we want to test, 2 arg agrument fo command line, 3 arg wait time
    Test.Observer();
	Test.modifyData("C:\\Users\\ADMIN\\source\\repos\\Json_Parser\\Json_Parser\\input00.json");
	//i - number of execution
	for (int i = 0; i < 100; i++){
		Test.modifyData("C:\\Users\\ADMIN\\source\\repos\\Json_Parser\\Json_Parser\\input00.json");
		Test.launcher("C:\\Users\\ADMIN\\source\\repos\\Json_Parser\\Json_Parser\\out\\build\\x64-Debug\\Project.exe", " C:\\Users\\ADMIN\\source\\repos\\Fuzzer\\out\\build\\x64-Debug\\Fuzzer\\out.txt", 1000);
		Test.Observer();
		
	}

    return 0;
}

bool Fuzz::launcher(char* path, char input[], DWORD wait_time)
{
    wait_timeA = wait_time;
    
    ZeroMemory(&cif, sizeof(STARTUPINFO));


    crproc = CreateProcess(path,       // target file name.
        input,               // command line options.
        NULL,                       // process attributes.
        NULL,                       // thread attributes.
        FALSE,                      // handles are not inherited.
        DEBUG_PROCESS,              // debug the target process and all spawned children.
        NULL,                       // use our current environment.
        NULL,                       // use our current working directory.
        &cif,                        // pointer to STARTUPINFO structure.
        &pi);                       // pointer to PROCESS_INFORMATION structure.

    if (!crproc)
    {
        fprintf(stderr, "[!] CreateProcess() failed: %d\n\n", GetLastError());
        return false;
    }

    
    return true;
}

char Fuzz::inputGenerator(){
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    int  len = rand();
    char* s;
    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
    return *s;
}

int Fuzz::Observer()
{
    DWORD start_time;
    start_time = GetTickCount();
    WCHAR* msg = new WCHAR[dbg.u.DebugString.nDebugStringLength];
    WCHAR* strEventMessage;
    while (GetTickCount() - start_time < wait_timeA)
    {
        if (WaitForDebugEvent(&dbg, 1000))
        {
            // we are only interested in debug events.
            if (dbg.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
            {
                ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, DBG_CONTINUE);
                continue;
            }

            // get a handle to the offending thread.
            if ((thread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbg.dwThreadId)) == NULL)
            {
                fprintf(stderr, "[!] OpenThread() failed: %d\n\n", GetLastError());
                return -1;
            }

            // get the context of the offending thread.
            context.ContextFlags = CONTEXT_FULL;

            if (GetThreadContext(thread, &context) == 0)
            {
                fprintf(stderr, "[!] GetThreadContext() failed: %d\n\n", GetLastError());
                return -1;
            }

            // examine the exception code.
            switch (dbg.u.Exception.ExceptionRecord.ExceptionCode)
            {
            case EXCEPTION_ACCESS_VIOLATION:
                exception = TRUE;
                printf("[*] Access Violation\n");
                break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                exception = TRUE;
                printf("[*] Divide by Zero\n");
                break;
            case EXCEPTION_STACK_OVERFLOW:
                exception = TRUE;
                printf("[*] Stack Overflow\n");
                break;
            default:
                printf("[*] Unknown Exception (%08x):\n", dbg.u.Exception.ExceptionRecord.ExceptionCode);
                ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, DBG_CONTINUE);
            }

            // if an exception occured, print more information.
            if (exception)
            {
                // open a handle to the target process.
                if ((process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dbg.dwProcessId)) == NULL)
                {
                    fprintf(stderr, "[!] OpenProcess() failed: %d\n\n", GetLastError());
                    return -1;
                }

				// grab some memory at EIP for disassembly.
				ReadProcessMemory(process, (void*)context.Rip, &inst_buf, 32, NULL);

				// decode the instruction into a string.
				//get_instruction(&inst, inst_buf, MODE_32);
				//get_instruction_string(&inst, FORMAT_INTEL, 0, inst_string, sizeof(inst_string));


                ReadProcessMemory(pi.hProcess,       // HANDLE to Debuggee
                    dbg.u.DebugString.lpDebugStringData, // Target process' valid pointer
                    msg,                           // Copy to this address space
                    dbg.u.DebugString.nDebugStringLength, NULL);
                strEventMessage = msg;
                wprintf(L"Process error in address :", strEventMessage);
                // print the exception to screen.
                printf("[*] Exception caught at %08x", context.Rdi);
                printf("[*] EAX:%08x EBX:%08x ECX:%08x EDX:%08x\n", context.Rax, context.Rbx, context.Rcx, context.Rdx);
                printf("[*] ESI:%08x EDI:%08x ESP:%08x EBP:%08x\n\n", context.Rsi, context.Rdi, context.Rsp, context.Rbp);

                return 1;
            }

        }
    }

    printf("[*] Process terminated normally.\n\n");
    return 0;
}

int Fuzz::modifyData(std::string path_to_file)
{
    //std::string path_to_file = "C:\\Users\\Dmitriy\\source\\repos\\Json_Parser\\Json_Parser\\input00.json";
    std::ifstream file;
    file.open(path_to_file);
    std::vector<char> vecArr;
    if (file.is_open())
    {
        while (!file.eof())
        {
            char c;
            file.read(&c, sizeof c);
            vecArr.push_back(c);
        }
    }
    else
    {
        printf("Error in get file");
        return -32;
    }

    srand(time(0));
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    auto value = alphanum[rand() % (sizeof(alphanum) - 1)];
    auto pos = rand() % (sizeof(vecArr) - 1);
    vecArr[pos] = value;

    ofstream fileout("out.txt");
    std::ostringstream oss;

    if (!vecArr.empty())
    {
        std::copy(vecArr.begin(), vecArr.end() - 1,
            std::ostream_iterator<int>(oss, ","));
        oss << vecArr.back();
    }
    std::string str(vecArr.begin(), vecArr.end());
    fileout << str;
    return 1;
}











