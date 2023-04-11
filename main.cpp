#include "mainwindow.h"

#include <QApplication>

BOOL mySetDebugPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    )
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if ( !LookupPrivilegeValue(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup
            &luid ) )        // receives LUID of privilege
    {
        //printf("LookupPrivilegeValue error: %u\n", GetLastError() );
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if ( !AdjustTokenPrivileges(
           hToken,
           FALSE,
           &tp,
           sizeof(TOKEN_PRIVILEGES),
           (PTOKEN_PRIVILEGES) NULL,
           (PDWORD) NULL) )
    {
          printf("AdjustTokenPrivileges error: %u\n", GetLastError() );
          return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
          printf("The token does not have the specified privilege. \n");
          return FALSE;
    }

    return TRUE;
}

BOOL mySetDebugPriv(BOOL onoff){
    HANDLE hToken = NULL;
    LUID PrivilegeRequired ;
    BOOL bRes = FALSE;
    DWORD er = 0;
    bRes = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &PrivilegeRequired);
    if( !bRes){
        er = GetLastError();
        return 0;
    }
    bRes = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_ALL_ACCESS, &hToken);
    if(!bRes) {
        er = GetLastError();
        return 0;
    }
    return mySetDebugPrivilege(hToken, SE_DEBUG_NAME, onoff);

}

int main(int argc, char *argv[])
{
    DWORD er = mySetDebugPriv(TRUE);

    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
