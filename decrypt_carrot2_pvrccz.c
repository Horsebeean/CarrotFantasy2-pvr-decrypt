#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#define dword_F9B03C ((int*)(decryption_key+0x3c))

unsigned char decryption_key[8192];

void goto_LABEL_23()
{
    printf("goto LABEL_23\n");
}

int main(int argc, char* argv[])
{
    char* inputFilePath = NULL;
    // get input filepath
    if(argc > 1)
    {
        inputFilePath = argv[1];
    }
    else
    {
        printf("decrypt_carrot2_pvrccz <filename> in CLI\nor drag input file to me.");
        exit(1);
    }
    

    // declarations from IDA Pseudocode
    int cczLen; // r8
    unsigned short *v5; // r0
    unsigned short *cczStartPtr; // r10
    int v10; // r3
    bool not_encrypted; // zf
    unsigned int *v13; // r2
    signed int v18; // r3
    unsigned int v19; // r6
    int v20; // r0
    int v21; // r8
    unsigned int v22; // r3
    int *v23; // r12
    signed int v24; // lr
    int v25; // r9
    int v26; // r0
    int v27; // r2
    signed int v28; // r1
    signed int v29; // r6
    int v30; // r0
    int v31; // r5
    int v32; // r6
    unsigned int v33; // [sp+0h] [bp-34h]
    int v34; // [sp+8h] [bp-2Ch]
    int v35; // [sp+10h] [bp-24h]

    
    // read decryption_key from file
    // from 0xF9B000 to 0xF9D000
    FILE* decryption_key_file =  fopen("decryption_key.bin", "rb");
    if(!decryption_key_file)
    {
        perror("failed to open file: decryption_key.bin");
        exit(1);
    }
    fread(decryption_key, 8192, 1, decryption_key_file);
    fclose(decryption_key_file);

    // read encrypted .pvr.ccz
    FILE* ccz_file =  fopen(inputFilePath, "rb");
    if(!decryption_key_file)
    {
        perror("failed to open the input .pvr.ccz file");
        exit(1);
    }
    fseek(ccz_file, 0, SEEK_END);
    unsigned int ccz_file_size = ftell(ccz_file);
    rewind(ccz_file);
    unsigned char* ccz_data = malloc(ccz_file_size);
    fread(ccz_data, ccz_file_size, 1, ccz_file);
    fclose(decryption_key_file);

    // debug
    printf("ccz_file_size = %d\n", ccz_file_size);
    printf("byte_F9C03C = %d\n", decryption_key[0x103C]);

    // decryption start
    cczLen = ccz_file_size;
    v5 = (unsigned short *)ccz_data;
    cczStartPtr = v5;
    v10 = *v5;
    if ( (v10 & 0xFFFFFF00) != 'C\0' )
    {
        goto_LABEL_23();
    }

    // ...
    v13 = (unsigned int *)(cczStartPtr + 6);
    v18 = (unsigned int)(cczLen - 12) >> 2;
    if(!decryption_key[0x103C])
    {
        v33 = (unsigned int)(cczLen - 12) >> 2;
        v19 = 0;
        v20 = 6;
        v34 = cczLen;
        v21 = dword_F9B03C[0];
        v22 = ((int *)(decryption_key+0x1038))[0];
        do
        {
            v35 = v20;
            v19 -= 1640531527;
            v23 = (int*) (&(decryption_key[0x40]));
            v24 = 1;
            v25 = (v19 >> 2) & 3;
            do
            {
            v26 = *v23;
            v27 = ((unsigned char)v24++ - 1) & 3;
            v22 = ((( ((int *)(decryption_key+0x2c))[v27 ^ v25] ^ v22) + (*v23 ^ v19)) ^ ((((unsigned int)*v23 >> 3) ^ 16 * v22)
                                                                    + (4 * *v23 ^ (v22 >> 5))))
                + v21;
            *(v23 - 1) = v22;
            ++v23;
            v21 = v26;
            }
            while ( v24 != 1024 );
            
            v21 = dword_F9B03C[0];
            v22 = ((( ((int *)(decryption_key+0x2c))[v25 ^ 3] ^ v22) + (dword_F9B03C[0] ^ v19)) ^ ((4 * dword_F9B03C[0] ^ (v22 >> 5))
                                                                            + (((unsigned int)dword_F9B03C[0] >> 3) ^ 16 * v22)))
                + ((int *)(decryption_key+0x1038))[0];
            ((int *)(decryption_key+0x1038))[0] = v22;
            v20 = v35 - 1;
        }
        while(v35 != 1);
        cczLen = v34;
        v13 = (unsigned int*)(cczStartPtr + 6);
        v18 = v33;
        decryption_key[0x103C] = 1;
    }


    v28 = 0;
    if(v18)
    {
        v29 = 0;
        do
        {
            v13[v28] ^= dword_F9B03C[v29];
            v30 = v29 + 1;
            ++v28;
            if ( v29 > 1022 )
            v30 = 0;
            if ( v28 >= v18 )
            break;
            v29 = v30;
        }
        while ( v28 < 512 );
    }
    else
    {
      v30 = 0;
    }


    for ( ; v28 < v18; v30 = v32 )
    {
      v31 = (int)(&cczStartPtr[2 * v28]);
      v28 += 64;
      *(int *)(v31 + 12) ^= dword_F9B03C[v30];
      v32 = v30 + 1;
      if ( v30 > 1022 )
        v32 = 0;
    }

    // CCZp -> CCZ!
    ccz_data[3] = '!';

    FILE* ccz_result_file = fopen(inputFilePath, "wb");
    fwrite(ccz_data, sizeof(unsigned char), ccz_file_size, ccz_result_file);
    fclose(ccz_result_file);
    
    // free memory
    free(ccz_data);
    ccz_data = NULL;

    return 0;
}