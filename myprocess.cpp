#include "myprocess.h"
#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <psapi.h>

myProcess::myProcess()
{    
    PID = 0;
    PIDPArent = 0;
}

myProcess& myProcess::operator= (const myProcess& other){
    this->PID = other.PID;
    this->PIDPArent = other.PID;
    this->nameParent = other.nameParent;
    this->name = other.name;
    this->nameOwner = other.nameOwner;
    this->DLL = other.DLL;
    this->Description = other.Description;
    this->PATH = other.PATH;
    this->SID = other.SID;
    this->x = other.x;

    return *this;
}

myProcess::myProcess(int newPID)
{
    PID = newPID;
    PIDPArent = 0;
}
void myProcess::setPID(DWORD PID){
    this->PID = PID;

}

void myProcess::getProcessName(){

    DWORD tempPID = this->PID;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, tempPID);
    if(hProc == 0){
        return;
    }
    else{

       /*wchar_t name[256];
       if (GetProcessImageFileName(hProc,name,256)){
           this->PATH.append(name);



       }
       CloseHandle(hProc);
        */
        HMODULE hMod;
        DWORD cbNeeded;
        TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
        if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded)){
            GetModuleBaseName(hProc, hMod, szProcessName, sizeof(szProcessName)/sizeof(TCHAR));
            this->name.append(szProcessName);
        }
        wchar_t szFilePath[MAX_PATH] = {0};
        GetModuleFileNameEx(hProc, NULL, szFilePath, MAX_PATH);
        this->PATH.append(szFilePath);
        CloseHandle(hProc);
    }
}

myProcess::~myProcess()
{
    DLL.clear();
}
