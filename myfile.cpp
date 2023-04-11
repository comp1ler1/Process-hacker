//#pragma comment(lib, "advapi32.lib")

#include "myfile.h"
#include "ui_myfile.h"

#include <windows.h>
#include <tchar.h>
#include "accctrl.h"
#include "aclapi.h"


#include <tlhelp32.h>
#include <processthreadsapi.h>
#include <sddl.h>
#include <wow64apiset.h>

#include <winbase.h>
#include <string.h>

#include <lmaccess.h>


#ifndef UNICODE
#define UNICODE
#endif
//#pragma comment(lib, "netapi32.lib")

#include <stdio.h>
#include <assert.h>
#include <windows.h>
#include <lm.h>

myFile::myFile(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::myFile)
{
    ui->setupUi(this);
}

myFile::~myFile()
{
    delete ui;
}

PSID getSID(std::wstring name){

    DWORD er = 0;
    PSID SIDpointer = NULL;
    DWORD countSID = 0;
    SID_NAME_USE peUse;
    TCHAR *domain = NULL;
    DWORD ulDomLen = 0;

    char Cname[] = "ilyak\0";

    er = LookupAccountNameA(NULL, Cname, SIDpointer, &countSID,(LPSTR) domain, &ulDomLen, &peUse);
    SIDpointer = (PSID)GlobalAlloc(
                GMEM_FIXED,
                countSID);
    domain = new TCHAR[ulDomLen];

    er = LookupAccountNameA(NULL, Cname, SIDpointer, &countSID,(LPSTR) domain, &ulDomLen, &peUse);

    return SIDpointer;
}

PSID getSID(std::string name){

    DWORD er = 0;
    PSID SIDpointer = NULL;
    DWORD countSID = 0;
    SID_NAME_USE peUse;
    TCHAR *domain = NULL;
    DWORD ulDomLen = 0;

    char Cname[] = "ilyak\0";

    er = LookupAccountNameA(NULL, Cname, SIDpointer, &countSID,(LPSTR) domain, &ulDomLen, &peUse);
    SIDpointer = (PSID)GlobalAlloc(
                GMEM_FIXED,
                countSID);
    domain = new TCHAR[ulDomLen];

    er = LookupAccountNameA(NULL, Cname, SIDpointer, &countSID,(LPSTR) domain, &ulDomLen, &peUse);

    return SIDpointer;
}


BOOL SetPrivilege(
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

BOOL mySetOwnPriv(BOOL onoff){
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
    return SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, onoff);

}

BOOL mySetPriv(BOOL onoff){
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
    return SetPrivilege(hToken, SE_SECURITY_NAME, onoff);

}


DWORD AddAceToObjectsSecurityDescriptor (
    LPTSTR pszObjName,          // name of object
    SE_OBJECT_TYPE ObjectType,  // type of object
    std::wstring pszTrustee,          // trustee for new ACE
    TRUSTEE_FORM TrusteeForm,   // format of trustee structure
    DWORD dwAccessRights,       // access mask for new ACE
    ACCESS_MODE AccessMode,     // type of ACE
    DWORD dwInheritance         // inheritance flags for new ACE
)
{
    DWORD dwRes = 0;
    PACL pOldSACL = NULL, pNewSACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;
    DWORD er = 0;

    PSID SID;
    //std::string name();

    er = mySetPriv(TRUE);


    wchar_t nm[256];
    for(int i = 0; i < pszTrustee.size() + 1; i++){
        nm[i] = pszTrustee.c_str()[i];
    }
    TrusteeForm = TRUSTEE_IS_NAME;


    if (NULL == pszObjName){
        er = GetLastError();
        return ERROR_INVALID_PARAMETER;
    }
    // Get a pointer to the existing DACL.

    dwRes = GetNamedSecurityInfo(pszObjName, ObjectType,
          SACL_SECURITY_INFORMATION,
          NULL, NULL, NULL, &pOldSACL, &pSD);
    if (ERROR_SUCCESS != dwRes) {
        //printf( "GetNamedSecurityInfo Error %u\n", dwRes );
        er = GetLastError();
        goto Cleanup;
    }

    // Initialize an EXPLICIT_ACCESS structure for the new ACE.

    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = dwAccessRights;
    ea.grfAccessMode = AccessMode;
    ea.grfInheritance= dwInheritance;
    ea.Trustee.TrusteeForm = TrusteeForm;
    ea.Trustee.ptstrName = nm;

    // Create a new ACL that merges the new ACE
    // into the existing DACL.

    dwRes = SetEntriesInAcl(1, &ea, pOldSACL, &pNewSACL);
    if (ERROR_SUCCESS != dwRes)  {
        //printf( "SetEntriesInAcl Error %u\n", dwRes );
        er = GetLastError();
        goto Cleanup;
    }

    // Attach the new ACL as the object's DACL.
    SID = getSID(pszTrustee);

    dwRes = SetNamedSecurityInfo(pszObjName, ObjectType,
          SACL_SECURITY_INFORMATION,
          SID, NULL, NULL, pNewSACL);
    if (ERROR_SUCCESS != dwRes)  {
        printf( "SetNamedSecurityInfo Error %u\n", dwRes );
        goto Cleanup;
    }

    Cleanup:

        if(pSD != NULL)
            LocalFree((HLOCAL) pSD);
        if(pNewSACL != NULL)
            //LocalFree((HLOCAL) pNewSACL);


        er = mySetPriv(FALSE);
        return dwRes;
}

void myFile::getUsers(){
    LPUSER_INFO_0 pBuf = NULL;
    LPUSER_INFO_0 pTmpBuf;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    DWORD i;
    DWORD dwTotalCount = 0;
    NET_API_STATUS nStatus;
    LPTSTR pszServerName = NULL;

    this->ui->comboBox->clear();
    this->ui->comboBox->addItem(QString("%1").arg(""));
    //
    // Call the NetUserEnum function, specifying level 0;
    //   enumerate global user account types only.
    //
    do // begin do
    {

       nStatus = NetUserEnum((LPCWSTR) pszServerName,
                             dwLevel,
                             FILTER_NORMAL_ACCOUNT, // global users
                             (LPBYTE*)&pBuf,
                             dwPrefMaxLen,
                             &dwEntriesRead,
                             &dwTotalEntries,
                             &dwResumeHandle);
       //
       // If the call succeeds,
       //
       if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
       {
          if ((pTmpBuf = pBuf) != NULL)
          {
             //
             // Loop through the entries.
             //
             for (i = 0; (i < dwEntriesRead); i++)
             {
                //assert(pTmpBuf != NULL);

                if (pTmpBuf == NULL)
                {
                   //fprintf(stderr, "An access violation has occurred\n");
                   break;
                }
                //
                //  Print the name of the user account.
                //
                //wprintf(L"\t-- %s\n", pTmpBuf->usri0_name);
                //this-> ui->listWidget_2->addItem(QString("%1").arg(pTmpBuf->usri0_name));
                this->ui->comboBox->addItem(QString("%1").arg(pTmpBuf->usri0_name));
                pTmpBuf++;
                dwTotalCount++;
             }
          }
       }
       //
       // Otherwise, print the system error.
       //

       //
       // Free the allocated buffer.
       //
       if (pBuf != NULL)
       {
          NetApiBufferFree(pBuf);
          pBuf = NULL;
       }
    }
    // Continue to call NetUserEnum while
    //  there are more entries.
    //
    while (nStatus == ERROR_MORE_DATA); // end do
    //
    // Check again for allocated memory.
    //
    if (pBuf != NULL)
       NetApiBufferFree(pBuf);
    //
    // Print the final count of users enumerated.
    //
    //fprintf(stderr, "\nTotal of %d entries enumerated\n", dwTotalCount);

    return;
 }

void myFile::on_lineEdit_returnPressed()
{
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    LPTSTR AcctName = NULL;
    LPTSTR DomainName = NULL;
    DWORD dwAcctName = 1, dwDomainName = 1;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD = NULL;

    LUID PrivilegeRequired ;
    DWORD iCount = 0;
    DWORD  dwLen = 0;
    BOOL bRes = FALSE;
    HANDLE hToken = NULL;
    BYTE *pBuffer = NULL;
    LPVOID myPBuffer = NULL;
    TOKEN_PRIVILEGES* pPrivs = NULL;

    DWORD er = 0;
    BOOL rec = false;

    ui->listWidget->clear();

    er = mySetPriv(TRUE);
    HeapFree(GetProcessHeap(), 0, pBuffer);

    this->getUsers();

    QString path;
    path = this->ui->lineEdit->text();
    std::wstring stringPath(path.toStdWString());
    hFile = CreateFile( stringPath.c_str(), GENERIC_READ | ACCESS_SYSTEM_SECURITY , FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        er = GetLastError();
              return;
    }
    PACL SACL = NULL;
    dwRtnCode = GetSecurityInfo(
                      hFile,
                      SE_FILE_OBJECT,
                      OWNER_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
                      &pSidOwner,
                      NULL,
                      NULL,
                      &SACL,
                      &pSD);
    if(dwRtnCode != ERROR_SUCCESS){
        return;
    }

    ULONG             pcCountOfExplicitEntries = NULL;
    EXPLICIT_ACCESS_A *pListOfExplicitEntries = NULL;
    if(GetExplicitEntriesFromAclA(SACL, &pcCountOfExplicitEntries, &pListOfExplicitEntries) != ERROR_SUCCESS){
        er = GetLastError();
    }


    for(int i = 0; i < pcCountOfExplicitEntries; i++){

        EXPLICIT_ACCESS_A nyt = pListOfExplicitEntries[i];

        /*if(i == 0){
            BOOL delsacl = DeleteAce(SACL, 1);
            delsacl = DeleteAce(SACL, 2);
        }*/

        std::string tempus, temtempus;
        tempus.append(pListOfExplicitEntries[i].Trustee.ptstrName);
        for(int j = 0; j < tempus.size(); j++){

            if(tempus.c_str()[j] < 10){
                char tempchar[2];
                tempchar[0] = tempus.c_str()[j] + 48;
                tempchar[1] = '\0';
                temtempus.append(tempchar);
                continue;
            }
            temtempus.append(" ");

        }
        switch(pListOfExplicitEntries[i].grfAccessMode){
        case 0:{
            ui->listWidget->addItem(QString("%1 %2 SID-%3").arg("NOT_USED_ACCESS").arg(pListOfExplicitEntries[i].grfAccessPermissions).arg(temtempus.c_str()));
            break;
        }
        case 1:{
            ui->listWidget->addItem(QString("%1 %2 SID-%3").arg("GRANT_ACCESS").arg(pListOfExplicitEntries[i].grfAccessPermissions).arg(temtempus.c_str()));
            break;
        }
        case 2:{
            ui->listWidget->addItem(QString("%1 %2 SID-%3").arg("SET_ACCESS").arg(pListOfExplicitEntries[i].grfAccessPermissions).arg(temtempus.c_str()));
            break;
        }
        case 3:{
            ui->listWidget->addItem(QString("%1 %2 SID-%3").arg("DENY_ACCESS").arg(pListOfExplicitEntries[i].grfAccessPermissions).arg(temtempus.c_str()));
            break;
        }
        case 4:{
            ui->listWidget->addItem(QString("%1 %2 SID-%3").arg("REVOKE_ACCESS").arg(pListOfExplicitEntries[i].grfAccessPermissions).arg(temtempus.c_str()));
            break;
        }
        case 5:{
            ui->listWidget->addItem(QString("%1 %2 SID-%3").arg("SET_AUDIT_SUCCESS").arg(pListOfExplicitEntries[i].grfAccessPermissions).arg(temtempus.c_str()));
            break;
        }
        case 6:{
            ui->listWidget->addItem(QString("%1 %2 SID-%3").arg("SET_AUDIT_FAILURE").arg(pListOfExplicitEntries[i].grfAccessPermissions).arg(temtempus.c_str()));
            break;
        }
        }


    }

    // Check GetLastError for GetSecurityInfo error condition.
    if (dwRtnCode != ERROR_SUCCESS) {
         er = GetLastError();
              //_tprintf(TEXT("GetSecurityInfo error = %d\n"), dwErrorCode);
              return;
    }

    // First call to LookupAccountSid to get the buffer sizes.
    bRtnBool = LookupAccountSid(
                      NULL,           // local computer
                      pSidOwner,
                      AcctName,
                      (LPDWORD)&dwAcctName,
                      DomainName,
                      (LPDWORD)&dwDomainName,
                      &eUse);

    // Reallocate memory for the buffers.
    AcctName = (LPTSTR)GlobalAlloc(
              GMEM_FIXED,
              dwAcctName);

    // Check GetLastError for GlobalAlloc error condition.
    if (AcctName == NULL) {
              //_tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);
              return;
    }

        DomainName = (LPTSTR)GlobalAlloc(
               GMEM_FIXED,
               dwDomainName);

        // Check GetLastError for GlobalAlloc error condition.
        if (DomainName == NULL) {
              //_tprintf(TEXT("GlobalAlloc error = %d\n"), dwErrorCode);

              return;

        }

        // Second call to LookupAccountSid to get the account name.
        bRtnBool = LookupAccountSid(
              NULL,                   // name of local or remote computer
              pSidOwner,              // security identifier
              AcctName,               // account name buffer
              (LPDWORD)&dwAcctName,   // size of account name buffer
              DomainName,             // domain name
              (LPDWORD)&dwDomainName, // size of domain name buffer
              &eUse);                 // SID type

        // Check GetLastError for LookupAccountSid error condition.
        if (bRtnBool == FALSE) {
              return;
        } else if (bRtnBool == TRUE){

            QString owner;
            owner.append(DomainName);
            owner.append("\\");
            owner.append(AcctName);

            PSTR tempstr;
            ConvertSidToStringSidA(pSidOwner, &tempstr);

            this->ui->lineEdit_4->setText(tempstr);
            this->ui->lineEdit_3->setText(owner);
        }

    er = mySetPriv(FALSE);
    CloseHandle(hToken);
    CloseHandle(hFile);

    if(pSD != NULL)
        LocalFree((HLOCAL) pSD);

    return;
}


void myFile::on_pushButton_clicked()
{
    QString Qtruefalse(this->ui->lineEdit_5->text()), QDwordRules(this->ui->lineEdit_6->text()), QSubject(this->ui->lineEdit_7->text()), QPath(this->ui->lineEdit->text());
    std::wstring Subject, Path;
    std::string truefalse, DwordRules;
    truefalse.append(Qtruefalse.toStdString().c_str());
    DwordRules.append(QDwordRules.toStdString().c_str());
    Subject.append(QSubject.toStdWString().c_str());
    Path.append(QPath.toStdWString().c_str());

    this->ui->label_2->clear();

    ACCESS_MODE AccessMode;
    switch(truefalse.c_str()[0] - 48){
    case 0:{
        AccessMode = NOT_USED_ACCESS;
        break;
    }
    case 1:{
        AccessMode = GRANT_ACCESS;
        break;
    }
    case 2:{
        AccessMode = SET_ACCESS;
        break;
    }
    case 3:{
        AccessMode = DENY_ACCESS;
        break;
    }
    case 4:{
        AccessMode = REVOKE_ACCESS;
        break;
    }
    case 5:{
        AccessMode = SET_AUDIT_SUCCESS;
        break;
    }
    case 6:{
        AccessMode = SET_AUDIT_FAILURE;
        break;
    }
    }

    //ACCESS_MODE AccessMode = truefalse.c_str()[0] - 48;
    DWORD rules = 0;
    for(int i = 0; i < DwordRules.size(); i++){
        rules = rules * 10 + (DwordRules.c_str()[i]-48);
    }
    wchar_t *array, *subarray, *subsubarray;
    array = (wchar_t*)malloc(Path.capacity() * sizeof(wchar_t));
    subarray = (wchar_t*)malloc(Subject.capacity() * sizeof(wchar_t));
    subsubarray = (wchar_t*)malloc(3 * sizeof(wchar_t));
    memcpy(array, Path.c_str(), Path.size() * sizeof(wchar_t));
    memcpy(subarray, Subject.c_str(), Subject.size() * sizeof(wchar_t));
    array[Path.size()] = '\0';
    subarray[Subject.size()] = '\0';

    subsubarray[0] = 1;
    subsubarray[1] = 5;
    subsubarray[2] = '\0';

    if(truefalse.size() == 0 || Path.size() == 0 || Subject.size() == 0 || DwordRules.size() == 0){

        return;
    }

    AddAceToObjectsSecurityDescriptor(array, SE_FILE_OBJECT, Subject, TRUSTEE_IS_SID, rules, AccessMode, NO_INHERITANCE);
}

void myFile::on_comboBox_currentTextChanged(const QString &arg1)
{

    QString path;
    path = this->ui->lineEdit->text();
    std::wstring stringPath(path.toStdWString());
    HANDLE hFile = CreateFile( stringPath.c_str(), GENERIC_READ | WRITE_OWNER , FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);



    std::string tempName(arg1.toStdString());
    if (tempName.size() == 0){
        return;
    }
    DWORD er = mySetOwnPriv(TRUE);
    PSID SIDpointer = getSID(tempName);

    if (hFile == INVALID_HANDLE_VALUE) {
        er = GetLastError();
              return;
    }

    mySetOwnPriv(TRUE);


    er = SetSecurityInfo(hFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, SIDpointer, NULL, NULL, NULL);

    if(er != ERROR_SUCCESS){
        er = GetLastError();
        QString out("Ошибка смены пользователя ");
        char num[20];
        itoa(er, num, 10);

        out.append(num);
        this->ui->label_2->setText(out);

        return;

    }

    QString out("Успешная смена пользователя!");
    this->ui->label_2->setText(out);
    return;
}

void myFile::on_pushButton_2_clicked()
{
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    LPTSTR AcctName = NULL;
    LPTSTR DomainName = NULL;
    DWORD dwAcctName = 1, dwDomainName = 1;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD = NULL;

    LUID PrivilegeRequired ;
    DWORD iCount = 0;
    DWORD  dwLen = 0;
    BOOL bRes = FALSE;
    HANDLE hToken = NULL;
    BYTE *pBuffer = NULL;
    LPVOID myPBuffer = NULL;
    TOKEN_PRIVILEGES* pPrivs = NULL;

    DWORD row = this->ui->listWidget->currentRow();
    if(row > this->ui->listWidget->count()){
        return;
    }


    DWORD er = 0;
    BOOL rec = false;


    er = mySetPriv(TRUE);
    HeapFree(GetProcessHeap(), 0, pBuffer);

    this->getUsers();

    QString path;
    path = this->ui->lineEdit->text();
    std::wstring stringPath(path.toStdWString());
    hFile = CreateFile( stringPath.c_str(), GENERIC_READ | ACCESS_SYSTEM_SECURITY , FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        er = GetLastError();
              return;
    }
    PACL SACL = NULL;
    dwRtnCode = GetSecurityInfo(
                      hFile,
                      SE_FILE_OBJECT,
                      OWNER_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
                      &pSidOwner,
                      NULL,
                      NULL,
                      &SACL,
                      &pSD);
    if(dwRtnCode != ERROR_SUCCESS){
        return;
    }

    ULONG             pcCountOfExplicitEntries = NULL;
    EXPLICIT_ACCESS_A *pListOfExplicitEntries = NULL;
    if(GetExplicitEntriesFromAclA(SACL, &pcCountOfExplicitEntries, &pListOfExplicitEntries) != ERROR_SUCCESS){
        er = GetLastError();
    }


    wchar_t *array;
    array = (wchar_t*)malloc(stringPath.capacity() * sizeof(wchar_t));
    memcpy(array, stringPath.c_str(), stringPath.size() * sizeof(wchar_t));
    array[stringPath.size()] = '\0';

    BOOL delsacl = DeleteAce(SACL, row);
    SE_OBJECT_TYPE ObjectType = SE_FILE_OBJECT;
    er = SetNamedSecurityInfo(array, ObjectType,
          SACL_SECURITY_INFORMATION,
          NULL, NULL, NULL, SACL);

    er = mySetPriv(FALSE);
    CloseHandle(hToken);
    CloseHandle(hFile);
}


