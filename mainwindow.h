#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>


#include <iostream>
#include <vector>

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);

    void setValues(class myProcess **array, DWORD cProcesses);

    ~MainWindow();
private slots:
    void update();
    void on_action_2_triggered();


    void on_action_4_triggered();

signals:
    void clicked();
private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
