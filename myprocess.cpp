#include "myprocess.h"
#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <psapi.h>

#include <tlhelp32.h>
#include <processthreadsapi.h>
#include <sddl.h>
#include <wow64apiset.h>
#pragma comment(lib, "advapi32.lib")

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

void myProcess::getPATH(){
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->PID);
    wchar_t szFilePath[MAX_PATH] = {0};
    GetModuleFileNameEx(hProc, NULL, szFilePath, MAX_PATH);
    this->PATH.append(szFilePath);
    CloseHandle(hProc);
}

void myProcess::getOName(){

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, this->PID);

    HANDLE TokenHandle;
    OpenProcessToken(hProc, TOKEN_QUERY, &TokenHandle);

    DWORD dwSize = 0;
    //PTOKEN_OWNER pOwnerInfo = (PTOKEN_OWNER) GlobalAlloc( GPTR, dwSize );
    if (GetTokenInformation(TokenHandle, TokenOwner , NULL, NULL, &dwSize)){
        CloseHandle(TokenHandle);
        CloseHandle(hProc);
        return;
    }
    PTOKEN_OWNER to = (PTOKEN_OWNER) LocalAlloc(LPTR, dwSize);
    if (!to)
    {
        CloseHandle(TokenHandle);
        CloseHandle(hProc);
        return;
    }

    if (!GetTokenInformation(TokenHandle, TokenOwner, to, dwSize, &dwSize))
       {
           //cerr << "GetTokenInformation failed, error " << dwError;
           LocalFree(to);
           CloseHandle(TokenHandle);
           CloseHandle(hProc);
           return;
       }

    char nameUser[256] = {0};
    char domainName[256] = {0};
    DWORD nameUserLen = 256;
    DWORD domainNameLen = 256;
    SID_NAME_USE snu;

    if (!LookupAccountSidA(NULL, to->Owner, nameUser, &nameUserLen, domainName, &domainNameLen, &snu))
    {
        LocalFree(to);
        CloseHandle(TokenHandle);
        CloseHandle(hProc);
        return;
    }
    nameUser[nameUserLen] = '\0';

    wchar_t WnameUser[nameUserLen + 1];
    mbstowcs(WnameUser, nameUser, nameUserLen);
    WnameUser[nameUserLen] = '\0';
    WnameUser[nameUserLen + 1] = '\0';
    this->nameOwner.append(WnameUser);

    PSTR tempstr;
    if(!ConvertSidToStringSidA(to->Owner, &tempstr)){
        CloseHandle(TokenHandle);
        CloseHandle(hProc);
        return;
    }

    std::string ts(tempstr);
    wchar_t WSIDUser[ts.capacity()];
    mbstowcs(WSIDUser, ts.c_str(), ts.capacity());
    WSIDUser[ts.size()] = '\0';
    WSIDUser[ts.size() + 1] = '\0';
    this->SID.append(WSIDUser);

    CloseHandle(TokenHandle);
    CloseHandle(hProc);
}

void myProcess::getX(){

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_READ, FALSE, this->PID);
    if(hProc == 0)
        return;

    if(this->PID == 6088){
        this->name.append(L"qu");
    }

    USHORT pProcessMachine, pNativeMachine;
    BOOL result = IsWow64Process2(hProc, &pProcessMachine, &pNativeMachine);
    IsWow64Process(hProc, &result);
    if(pNativeMachine == 34404){
        //x64 OS
        if (pProcessMachine != IMAGE_FILE_MACHINE_UNKNOWN && pProcessMachine == 332){
            this->x.append(L"x32");
        }
        else{
            this->x.append(L"x64");
        }
    }
    else{
        if(pNativeMachine == 332){
            //x32 OS
            if (result == false){
                this->x.append(L"x32");
            }
        }
    }


    CloseHandle(hProc);
}

void myProcess::getProcessInfo(){

    this->getPATH();
    this->getOName();
    this->getX();
}

myProcess::~myProcess()
{

}
