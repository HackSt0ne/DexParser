#include "dexhelper.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[])
{
    printf("[*] start parse dex file\n");    

    if(argc != 2)
    {
        printf("<usage> dexparser dexfilename\n");
        return 0;
    }

    char* dex_filepath = argv[1];
    //const char* dex_filepath = "./Hello.dex";
    
    FILE* dex_file = fopen(dex_filepath, "rb+");
    if(dex_file == NULL)
    {
        printf("[*] open file failed\n");
        return 0;
    }

    fseek(dex_file, 0, SEEK_END);
    int file_szie = ftell(dex_file);
    fseek(dex_file, 0, SEEK_SET);

    if(file_szie == 0)
    {
        printf("[*] file size = 0\n");
        fclose(dex_file);
        dex_file = NULL;
        return 0;
    }

    char* dex_buf = (char* )malloc(file_szie);
    if(dex_buf == NULL)
    {
        printf("[*] malloc failed\n");
        fclose(dex_file);
        dex_file = NULL;
        return 0;
    }
    memset(dex_buf, 0, file_szie);

    int read = fread(dex_buf, 1,file_szie,  dex_file);
    if(read != file_szie)
    {
        printf("[*] fread failed: %d %d\n", read, file_szie);
        fclose(dex_file);
        free(dex_buf);
        return 0;
    }

    DexHelper helper;
    helper.Parse(dex_buf, file_szie);
    
    fclose(dex_file);
    free(dex_buf);
    return 0;
}
