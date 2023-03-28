#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "infoProcess.cpp"
#include "myprocess.h"

#include <psapi.h>
#include    <tlhelp32.h>
#include <processthreadsapi.h>
#include <sddl.h>
#include <wow64apiset.h>

void setPidNamePPID(class myProcess **array, DWORD cProcesses){

    DWORD now = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0 );
    PROCESSENTRY32 pe32;
    std::wstring tempPrev;
    if( hSnapshot == INVALID_HANDLE_VALUE )
        return;
        ZeroMemory( &pe32, sizeof( pe32 ) );
        pe32.dwSize = sizeof( pe32 );

        Process32First( hSnapshot, &pe32 );
        do{
            array[now]->PID = pe32.th32ProcessID;
            array[now]->PIDPArent = pe32.th32ParentProcessID;
            array[now]->name.append(pe32.szExeFile);

            int i = 0;
            for(; array[i]->PIDPArent != pe32.th32ParentProcessID; i++){}
            array[now]->nameParent.append(array[i]->name);

            now++;
        }while( Process32Next( hSnapshot, &pe32 ) );
    if( hSnapshot != INVALID_HANDLE_VALUE )
        CloseHandle( hSnapshot );

    for(DWORD i = 0; i < cProcesses; i++){
        array[i]->getProcessInfo();
    }

}

void MainWindow::setValues(class myProcess **array, DWORD cProcesses)
{
    ui->tableWidget->setRowCount(cProcesses); // указываем количество строк
    ui->tableWidget->setColumnCount(12);

    for(int stroka = 0; stroka < ui->tableWidget->rowCount(); stroka++)
      for(int stolbeu = 0; stolbeu < ui->tableWidget->columnCount(); stolbeu++)
      {
           QTableWidgetItem *item = new QTableWidgetItem(); // выделяем память под ячейку

           if(stolbeu == 0){
                item->setText(QString("%1").arg(array[stroka]->PID));
           }
           if(stolbeu == 1){
                item->setText(QString("%1").arg(array[stroka]->name));
           }
           if(stolbeu == 2){
                item->setText(QString("%1").arg(array[stroka]->PATH));
           }
           if(stolbeu == 3){
                item->setText(QString("%1").arg(array[stroka]->PIDPArent));
           }
           if(stolbeu == 4){
                item->setText(QString("%1").arg(array[stroka]->nameParent));
           }
           if(stolbeu == 5){
                item->setText(QString("%1").arg(array[stroka]->nameOwner));
           }
           if(stolbeu == 6){
                item->setText(QString("%1").arg(array[stroka]->SID));
           }
           if(stolbeu == 7){
                item->setText(QString("%1").arg(array[stroka]->x));
           }
           ui->tableWidget->setItem(stroka, stolbeu, item); // вставляем ячейку
      }
}

void MainWindow::update()
{

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
    {
        //return 1;
    }

    cProcesses = cbNeeded / sizeof(DWORD);
    myProcess* array[cProcesses];
    for(DWORD i = 0; i < cProcesses; i++){
        array[i] = new myProcess(aProcesses[i]);
    }

    setPidNamePPID(array, cProcesses);
    setValues(array, cProcesses);
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded );
    cProcesses = cbNeeded / sizeof(DWORD);
    myProcess* array[cProcesses];
    for(DWORD i = 0; i < cProcesses; i++){
        array[i] = new myProcess(aProcesses[i]);
    }

    setPidNamePPID(array, cProcesses);

    // выделяем память под все ячейки таблицы
    for(int stroka = 0; stroka <   ui->tableWidget->rowCount(); stroka++)
    for(int stolbeu = 0; stolbeu <   ui->tableWidget->columnCount(); stolbeu++)
        ui->tableWidget->setItem(stroka, stolbeu, new QTableWidgetItem());

    setValues(array, cProcesses);


    QStringList horzHeaders;
    horzHeaders << "PID" << "Name" << "Path" << "PPID" << "PName" << "OName" << "SID" << "x32/x64";
    ui->tableWidget->setHorizontalHeaderLabels( horzHeaders );

    //Установка прерывания для кнопки обновления
    QPushButton *upd = ui->pushButton;
    connect(upd, SIGNAL(clicked()), this, SLOT(update()));

    for(DWORD i = 0; i < cProcesses; i++){
        delete array[i];
    }
}

MainWindow::~MainWindow()
{
    delete ui;
}
