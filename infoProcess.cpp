#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

#include "myprocess.h"




class myProcess* getListProcess(){

    DWORD aProcesses[1024], cbNeeded, cProcesses;

        if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
        {
            //return 1;
        }

        cProcesses = cbNeeded / sizeof(DWORD);
        myProcess* array[400];
        for(DWORD i = 0; i < cProcesses; i++){
            array[i] = new myProcess(aProcesses[i]);
        }

        return *array;
}
