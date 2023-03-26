#include "myprocess.h"
#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <psapi.h>

#include    <tlhelp32.h>
#include <processthreadsapi.h>
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

void myProcess::getName(){
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->PID);
    HMODULE hMod;
    DWORD cbNeeded;
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded)){
        GetModuleBaseName(hProc, hMod, szProcessName, sizeof(szProcessName)/sizeof(TCHAR));
        this->name.append(szProcessName);
    }
    CloseHandle(hProc);
}

void myProcess::getPATH(){
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->PID);
    wchar_t szFilePath[MAX_PATH] = {0};
    GetModuleFileNameEx(hProc, NULL, szFilePath, MAX_PATH);
    this->PATH.append(szFilePath);
    CloseHandle(hProc);
}

void myProcess::getPPID(){
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0 );
    PROCESSENTRY32 pe32;
    DWORD ppid = 0;

    if( hSnapshot == INVALID_HANDLE_VALUE )
        return;
        ZeroMemory( &pe32, sizeof( pe32 ) );
        pe32.dwSize = sizeof( pe32 );

        if( !Process32First( hSnapshot, &pe32 ) )
            return;

        do{
            if( pe32.th32ProcessID == this->PID ){
                ppid = pe32.th32ParentProcessID;
                break;
            }
        }while( Process32Next( hSnapshot, &pe32 ) );
    if( hSnapshot != INVALID_HANDLE_VALUE )
        CloseHandle( hSnapshot );
    this->PIDPArent = ppid;
}

void myProcess::getPName(){
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->PIDPArent);
    HMODULE hMod;
    DWORD cbNeeded;
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &cbNeeded)){
        GetModuleBaseName(hProc, hMod, szProcessName, sizeof(szProcessName)/sizeof(TCHAR));
        this->nameParent.append(szProcessName);
    }
    CloseHandle(hProc);
}

void myProcess::getOName(){

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, this->PID);

    HANDLE TokenHandle;
    OpenProcessToken(hProc, TOKEN_QUERY, &TokenHandle);

    DWORD dwSize = 0;
    //PTOKEN_OWNER pOwnerInfo = (PTOKEN_OWNER) GlobalAlloc( GPTR, dwSize );
    DWORD dwError;
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
           dwError = GetLastError();
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
        dwError = GetLastError();
        //cerr << "LookupAccountSid failed, error " << dwError;
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

    CloseHandle(TokenHandle);
    CloseHandle(hProc);
}

void myProcess::getProcessInfo(){

    this->getName();
    this->getPATH();
    this->getPPID();
    this->getPName();
    this->getOName();
}

myProcess::~myProcess()
{
    DLL.clear();
}
