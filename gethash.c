#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "hash_helper.h"

#define UNUSED(var) ((void) var)

int main(int argc, char *argv[])
{
    int i = 1;
    bool md5 = false;
    bool exor = false;
    bool crc16 = false;
    bool crc32 = false;
    bool file = false;
    char *filename = NULL;
    bool hexadecimal = false;
    //READING INPUT FROM COMMAND LINE
    while(argv[i] != NULL){
        if(strcmp(argv[i],"-xor")==0){
            if(exor == true){
                fprintf( stderr, "argument specified more than once");
                return 1;
            } else {
                exor = true;
            }
        }
        else if(strcmp(argv[i],"-c16")==0){
            if(crc16 == true){
                fprintf( stderr, "argument specified more than once");
                return 1;
            } else {
                crc16 = true;
            }
        }
        else if(strcmp(argv[i],"-c32")==0){
            if(crc32 == true){
                fprintf( stderr, "argument specified more than once");
                return 1;
            } else {
                crc32 = true;
            }
        }
        else if(strcmp("-md5", argv[i])==0){
            if(md5 == true){
                fprintf( stderr, "argument specified more than once");
                return 1;
            } else {
                md5 = true;
            }
        }
        else if(strcmp(argv[i],"-f")==0){
            if((i+1)== argc || file == true){
                fprintf( stderr, "File non existent");
                return 1;
            } else {
                file = true;
                filename = argv[i+1];
                i++;
            }
        }
        else if(strcmp(argv[i], "-hex")==0){
            if(hexadecimal == true){
                fprintf( stderr, "argument specified more than once");
                return 1;
            } else {
                hexadecimal = true;
            }
        } else {
            fprintf( stderr, "Unknown argument");
            return 1;
        }
        i++;
    }
    if(!exor && !md5 && !crc16 && ! crc32){
        fprintf( stderr, "At least one hash must be specified.");
        return 1;
    }
    if(file){
        FILE *doesExist = fopen (filename, "rb");
        if(doesExist == NULL){
            fprintf( stderr, "File doesn't exist");
            return 1;
        }
        int bytes;
        unsigned long size = 0;
        bool xorInitiated = false;
        unsigned char data[512];
        unsigned short contextXOR = 0;
        crc16_context *ctx16 = malloc(sizeof(crc16_context));
        unsigned int context32 = -1;
        MD5_CTX mdContext;
        if(crc16){
            crc16_init(ctx16);
        }
        if(md5){
            MD5_Init (&mdContext);
        }
        while ((bytes = fread (data, sizeof(char), 512, doesExist)) != 0){
            size += bytes;
            if(exor){
                if(!xorInitiated){
                    contextXOR = XOR1(contextXOR, data, bytes);
                    xorInitiated = true;
                } else {
                    contextXOR = XOR2(contextXOR, data, bytes);
                }
            }
            if(crc16){
                int j = 0;
                while(j < bytes){
                    crc16_update(ctx16, data[j]);
                    j++;
                }
            }
            if(crc32){
                context32 = crc32_calculate(data, context32, bytes);
            }
            if(md5){
                MD5_Update (&mdContext, data, bytes);
            }
        }
        printf("Length: %li bytes\n", size);
        if(exor){
            if(hexadecimal){
                printf("XOR: 0x%02x\n", contextXOR);
            } else {
                printf("XOR: %u\n", contextXOR);
            }
        }
        if(crc16){
            if(hexadecimal){
                printf("CRC-16: 0x%02x\n", ctx16->crc);
            } else {
                printf("CRC-16: %u\n", ctx16->crc);
            }
        }
        if(crc32){
            context32 = crc32_final(context32);
            if(hexadecimal){
                if(context32 == 0){
                    printf("CRC-32: 0x00000000\n");
                } else {
                   printf("CRC-32: 0x%02x\n", context32);
                }
            } else {
                printf("CRC-32: %u\n", context32);
            }
        }
        if(md5){
            int i;
            unsigned char result[16];
            MD5_Final (result,&mdContext);
            printf("MD5: ");
            for(i = 0; i < 16; i++) printf("%02x", result[i]);
            printf("\n");
        }
        free(ctx16);
        fclose(doesExist);
    }

    else{
        int bytes;
        MD5_CTX mdContext;
        crc16_context *ctx16 = malloc(sizeof(crc16_context));
        unsigned short contextXOR = 0;;
        bool xorInitiated = false;
        unsigned int context32 = -1;
        unsigned long size = 0;
        if(crc16){
            crc16_init(ctx16);
        }
        if(md5){
            MD5_Init (&mdContext);
        }
        unsigned char data[512];
        do{
            bytes = fread(data, sizeof(char), 512, stdin);
            size += bytes;
            if(exor && bytes){
                if(!xorInitiated){
                    contextXOR = XOR1(contextXOR, data, bytes);
                    xorInitiated = true;
                } else {
                    contextXOR = XOR2(contextXOR, data, bytes);
                }
            }
            if(crc16){
                int j = 0;
                while(j < bytes){
                    crc16_update(ctx16, data[j]);
                    j++;
                }
            }
            if(crc32){
                context32 = crc32_calculate(data, context32, bytes);
            }
            if(md5){
                MD5_Update (&mdContext, data, bytes);
            }
        } while(bytes == 512);
        printf("Length: %li bytes\n", size);
        if(exor){
            if(hexadecimal){
                printf("XOR: 0x%02x\n", contextXOR);
            } else {
                printf("XOR: %u\n", contextXOR);
            }
        }
        if(crc16){
            if(hexadecimal){
                printf("CRC-16: 0x%02x\n", ctx16->crc);
            } else {
                printf("CRC-16: %u\n", ctx16->crc);
            }
        }
        if(crc32){
            context32 = crc32_final(context32);
            if(hexadecimal){
                if(context32 == 0){
                    printf("CRC-32: 0x00000000\n");
                } else {
                   printf("CRC-32: 0x%02x\n", context32);
                }
            }
            else{
                printf("CRC-32: %u\n", context32);
            }
        }
        if(md5){
            int i;
            unsigned char result[16];
            MD5_Final (result,&mdContext);
            printf("MD5: ");
            for(i = 0; i < 16; i++) printf("%02x", result[i]);
            printf("\n");
        }
        free(ctx16);
    }
    return 0;
}

