#ifndef MYPROCESS_H
#define MYPROCESS_H

#include <iostream>
#include <vector>

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

using namespace std;

class myProcess
{
public:
    myProcess();
    myProcess(int newPID);
    ~myProcess();
    void setPID(DWORD PID);

    void getProcessName();

    myProcess& operator= (const myProcess& other);

    std::wstring name;
    std::string Description;
    std::wstring PATH;
    std::string nameParent;
    std::string nameOwner;
    std::string SID;
    std::string x;

    std::vector<std::string> DLL;

    int PID;
    int PIDPArent;
};

#endif // MYPROCESS_H
