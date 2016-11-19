#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/aes.h>


void decryptfile(FILE * fpin,FILE* fpout,unsigned char* key, unsigned char* iv);
void ls_dir(char* start_path);

void main()
{

        char* start_path;									  //start_path라는 char형 포인터만듬
        start_path = "/home/";								  //그안에 /home/ 을 넣음
        ls_dir(start_path);									  //
}

void ls_dir(char* start_path)									  // ls_dir은 char형 포인터를 하나받아서 반환없음
{
	unsigned char key[] = "12345678901234561234567890123456";		  //32 chars long 부호없는 char형 변수로 key배열 만들고 그안에 문자32개넣음
    unsigned char iv[] = "1234567890123456";						  //16 chars long 부호없는 char형 변수로 iv배열만들고 그안에 문자 16개넣음  
	DIR* dir;												  //dirent.h에 있는 dir구조체로 dir포인터 선언
	struct dirent *ent;										  /*dirent 개방한 파일의 정보를 저장할 구조체 변수
														  long d_ino;
														  off_t d_off;						  <-- 이렇게생김
														  unsigned short d_recien;
														  char d_name[NAME_MAX+1];
														  unsigned char d_type;
														  ent포인터선언
													       */
	if((dir=opendir(start_path)) !=NULL)						  //start_path(/home/)을 열고 dir에 넣는다 성공해서 NULL이 아닌값이 반환됬다면 if문진입
	{
		while((ent=readdir(dir)) !=NULL)						  //연 디렉토리를 읽어서 ent에 넣음
		{

			if(ent->d_type == 8)							  //열은 디렉토리의 d_type이 8이면 (REG파일)
			{

				int len = strlen(ent->d_name);				  //이름의 길이를 len에 저장하고
				const char* last_four = &ent->d_name[len-4];		  //last_four라는곳에 폴더이름뒤의 4글자를빼고 저장
				if(strcmp(last_four,".enc") == 0)				  //last_four과 .enc가 같지않으면진입
				{

					char* full_path =(char*) malloc(strlen(ent->d_name)+strlen(start_path)+2);	    //full_path에 (/home/길이+2) +(폴더이름길이) 크기로 동적할당
					strcpy(full_path,start_path);										    // /home/이 full_path에 복사됨
					strcat(full_path,ent->d_name);									    // full_path뒤에 폴더명 붙임
					char* new_name = (char*) malloc(strlen(full_path)+1);					//new_name으로 full_path보다 1크게 동적할당
					strcpy(new_name,full_path);										   //new_name에 full_path 복사
					new_name[strlen(new_name)-4] = '\0';								   //new_name의 마지막에서 4번째문자를 없앰

					FILE* fpin;													//폴더여는거
					FILE* fpout;													//폴더닫는거

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

	EVP_CipherInit(&ctx,EVP_aes_256_cbc(),key,iv,0); // 0 = decrypt 	1= encrypt
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

