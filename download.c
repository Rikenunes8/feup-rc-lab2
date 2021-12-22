
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>


struct args_t {
  char protocol[100];
  char user[100];
  char pass[100];
  char host[100];
  char path[100];
};

int connect_socket(char* addr, int port) {
  int sockfd;
  struct sockaddr_in server_addr;
  size_t bytes;

  /*server address handling*/
  bzero((char *) &server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(addr);    /*32 bit Internet address network byte ordered*/
  server_addr.sin_port = htons(port);        /*server TCP port must be network byte ordered */

  /*open a TCP socket*/
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket()");
    exit(-1);
  }
  /*connect to the server*/
  int res = connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
  if (res < 0) {
    perror("connect()");
    exit(-1);
  }
  return sockfd;
}

int disconnect_socket(int sockfd) {
  if (close(sockfd)<0) {
    perror("close()");
    exit(-1);
  }
  return 0;
}

int hostname_to_IP(char* hostname, char* ip) {
  struct hostent *h;
  h = gethostbyname(hostname);
  if (h == NULL) {
    herror("gethostbyname()");
    exit(-1);
  }
  strcpy(ip, inet_ntoa(*((struct in_addr *) h->h_addr)));

  printf("Host name  : %s\n", h->h_name);
  printf("IP Address : %s\n", ip);

  return 0;
}

int get_port(char* protocol) {
  if      (strcmp(protocol, "ftp"))   return 21;
  else if (strcmp(protocol, "ssh"))   return 22;
  else if (strcmp(protocol, "smtp"))  return 25;
  else if (strcmp(protocol, "http"))  return 80;
  else if (strcmp(protocol, "pop3"))  return 110;
  else                                return -1;
}

int parse_args(struct args_t* args, int argc, char** argv) {
  if (argc != 2) {
    printf("Wrong number of arguments\n");
    printf("usage: download ftp://[<user>:<password>@]<host>/<url-path>\n");

    return -1;
  }
  
  char* ptrI = argv[1];
  char* ptrJ = argv[1];
  const char* endPtr = argv[1]+strlen(argv[1]);
  int size;
  int state = 0;

  char* at = strchr(argv[1], '@');
  bool hasLogin = at != NULL;
  
  while (ptrJ < endPtr && state != 5) {
    switch (state) {
      case (0):
        if (*ptrJ == ':' && *(ptrJ+1) == '/' && *(ptrJ+2) == '/') {
          size = ptrJ-ptrI;
          strncpy(args->protocol, ptrI, size);
          ptrJ += 3;
          ptrI = ptrJ;
          state = hasLogin ? 1 : 3;
        }
        break;
      case (1):
        if (*ptrJ == ':') {
          size = ptrJ-ptrI;
          strncpy(args->user, ptrI, size);
          ptrI = ptrJ+1;
          state = 2;
        }
        break;
      case (2):
        if (*ptrJ == '@') {
          size = ptrJ-ptrI;
          strncpy(args->pass, ptrI, size);
          ptrI = ptrJ+1;
          state = 3;
        }
        break;
      case (3):
        if (*ptrJ == '/') {
          size = ptrJ-ptrI;
          strncpy(args->host, ptrI, size);
          ptrI = ptrJ+1;
          state = 4;
        }
        else if (ptrJ == endPtr-1) {
          size = ptrJ-ptrI+1;
          strncpy(args->host, ptrI, size);
        }
        break;
      case (4):
        size = endPtr-ptrI;
        strncpy(args->path, ptrI, size);
        ptrI = ptrJ+1;
        state = 5;
        break;
      default:
        break;
    }
    ptrJ++;
  }
  

  if (hasLogin && args->user == NULL && args->pass == NULL || args->host == NULL) {
    printf("Bad input\n");
    printf("usage: download ftp://[<user>:<password>@]<host>/<url-path>\n");
    return -1;
  }

  printf("%s\n", args->protocol);
  printf("%s\n", args->user);
  printf("%s\n", args->pass);
  printf("%s\n", args->host);
  printf("%s\n", args->path);
  return 0;
}


int main(int argc, char** argv) {
  struct args_t args = {"", "", "", "", ""};
  parse_args(&args, argc, argv);

  
  
}