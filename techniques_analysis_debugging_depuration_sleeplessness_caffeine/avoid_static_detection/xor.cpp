#include <windows.h>
#include <iostream>
#include <cstring>

char* xor_decrypt(const char* input, char key){
    size_t len = strlen(input);
    char* output = new char[len + 1];
    for (size_t i = 0; i < len; ++i){
        output[i] = input[i] ^ key;
    }
    
    output[len] = '\0';
    
    return output;
}

int main(){
    const char* enc_cmd = "\x36\x38\x31\x7b\x30\x30";
    char* cmd = xor_decrypt(enc_cmd, 0x55);
    WinExec(cmd, SW_HIDE);
    delete[] cmd;
    return 0;
}