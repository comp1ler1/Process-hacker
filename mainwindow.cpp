#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "infoProcess.cpp"
#include "myprocess.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);


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

    for(DWORD i = 0; i < cProcesses; i++){
        array[i]->getProcessName();
    }

    //myProcess *array = getListProcess();

    ui->tableWidget->setRowCount(cProcesses); // указываем количество строк
        ui->tableWidget->setColumnCount(12); // указываем количество столбцов

        // выделяем память под все ячейки таблицы
        for(int stroka = 0; stroka <   ui->tableWidget->rowCount(); stroka++)
        for(int stolbeu = 0; stolbeu <   ui->tableWidget->columnCount(); stolbeu++)

            ui->tableWidget->setItem(stroka, stolbeu, new QTableWidgetItem());


        // выделяем память под все ячейки таблицы
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
               //item->setText(QString("%1_%2").arg(stroka).arg(stolbeu)); // вставляем текст
               ui->tableWidget->setItem(stroka, stolbeu, item); // вставляем ячейку
          }

        QStringList horzHeaders;
        horzHeaders << "PID" << "Name" << "Path";
        //ui->tableWidget->setRowCount( 3 - 1 );
        //ui->tableWidget->setColumnCount( columnHeaderList[0].size() );
        ui->tableWidget->setHorizontalHeaderLabels( horzHeaders );

}

MainWindow::~MainWindow()
{
    delete ui;
}

