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
    void setPATH();
    void setProcessInfo();
    void setOName();
    void setX();
    myProcess& operator= (const myProcess& other);

    std::wstring name;
    std::wstring Description;
    std::wstring PATH;
    std::wstring nameParent;
    std::wstring nameOwner;
    std::wstring SID;
    std::wstring x;
    std::vector<std::string> DLL;
    int PID;
    int PIDPArent;
};

#endif // MYPROCESS_H
