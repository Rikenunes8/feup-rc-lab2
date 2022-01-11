
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>


struct args_t {
  char protocol[100];
  char user[100];
  char pass[100];
  char host[100];
  char path[100];
  char filename[30];
  char ip[20];
  int port;
};


int get_port(char* protocol) {
  if      (strcmp(protocol, "ftp") == 0)  return 21;
  else if (strcmp(protocol, "ssh") == 0)  return 22;
  else if (strcmp(protocol, "smtp") == 0) return 25;
  else if (strcmp(protocol, "http") == 0) return 80;
  else if (strcmp(protocol, "pop3") == 0) return 110;
  else                                    return -1;
}

int parse_args(struct args_t* args, int argc, char** argv) {
  if (argc != 2) {
    printf("Wrong number of arguments\n");
    printf("usage: download ftp://[<user>:<password>@]<host>/<url-path>\n");
    return -1;
  }
  
  char* ptrI = argv[1];
  char* ptrJ = argv[1];
  char* endPtr = argv[1]+strlen(argv[1]);
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
  
  args->port = get_port(args->protocol);

  if (hasLogin && args->user == NULL && args->pass == NULL || args->host == NULL || args->port < 0) {
    printf("Bad input\n");
    return -1;
  }

  if (args->path != NULL) {
    char* ptr = endPtr-1;
    while (*(ptr--) != '/');
    strncpy(args->filename, ptr+2, endPtr-ptr-2);
  }


  printf("%s\n", args->protocol);
  printf("%s\n", args->user);
  printf("%s\n", args->pass);
  printf("%s\n", args->host);
  printf("%s\n", args->path);
  printf("%s\n", args->filename);
  printf("%d\n", args->port);
  return 0;
}

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


int ftp_send_cmd(int socket, char* cmd) {
  int ret = send(socket, cmd, strlen(cmd), 0);
  if (ret < 0) {
    printf("Fail to send cmd '%s'", cmd);
    return -1;
  }
  return ret;
}

int ftp_recv_resp(int socket, char* buffer, int len) {
  char code[3];
  memset(buffer, 0, len);
  memset(code, 0, 3);
  int off = 0;
  while (len != off) {
    int ret = recv(socket, &buffer[off], len-off, 0);
    if (ret > 3 && buffer[off+3] != '-' || ret == 3) {
      strncpy(code, &buffer[off], 3);
      break;
    }
    else if (ret < 0) {
      printf("Fail to recv from socket\n");
      return -1;
    }
    off += ret;
  }
  printf("%s", buffer);

  return atoi(code);
}


void download_file(int socket, char* filename, char* buffer, int len) {
  int fd = open(filename, O_WRONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO );
  while (true) {
    memset(buffer, 0, len);
    int ret = recv(socket, buffer, len, 0);
    if (ret < 0) {
      printf("Fail to recv from socket\n");
      return;
    }
    write(fd, buffer, ret);
    if (ret != len) {
     break;
    }
  }
  close(fd);
}

int main(int argc, char** argv) {
  struct args_t args = {"", "", "", "", "", -1};
  if (parse_args(&args, argc, argv) < 0) {
    printf("usage: download ftp://[<user>:<password>@]<host>/<url-path>\n");
    return -1;
  }

  if (strlen(args.user) == 0 && strlen(args.pass) == 0) {
    strcpy(args.user, "anonymous");
    strcpy(args.pass, "anonymous");
  }

  char cmd[200];
  char res[1000];

  hostname_to_IP(args.host, args.ip);

  int term_A = connect_socket(args.ip, args.port);
  ftp_recv_resp(term_A, res, 1000);
  
  sprintf(cmd, "USER %s\r\n", args.user);
  printf("\ncmd: %s\n", cmd);
  ftp_send_cmd(term_A, cmd);
  ftp_recv_resp(term_A, res, 1000);
  
  sprintf(cmd, "PASS %s\r\n", args.user);
  printf("\ncmd: %s\n", cmd);
  ftp_send_cmd(term_A, cmd);
  ftp_recv_resp(term_A, res, 1000);

  sprintf(cmd, "TYPE I\r\n");
  printf("\ncmd: %s\n", cmd);
  ftp_send_cmd(term_A, cmd);
  ftp_recv_resp(term_A, res, 1000);

  sprintf(cmd, "PASV\r\n");
  printf("\ncmd: %s\n", cmd);
  ftp_send_cmd(term_A, cmd);
  ftp_recv_resp(term_A, res, 1000);

  int a, b, c, d, pa, pb;
  char* start = strchr(res, '(');
  char ip_host[32];
  int port;
	sscanf(start, "(%d,%d,%d,%d,%d,%d)", &a, &b, &c, &d, &pa, &pb);
	sprintf(ip_host, "%d.%d.%d.%d", a, b, c, d);
  port = 256*pa + pb;

  int term_B = connect_socket(ip_host, port);
  
  sprintf(cmd, "RETR %s\r\n", args.path);
  printf("\ncmd: %s\n", cmd);
  ftp_send_cmd(term_A, cmd);
  ftp_recv_resp(term_A, res, 1000);
  ftp_recv_resp(term_A, res, 1000);

  download_file(term_B, args.filename, res, 1000);

  disconnect_socket(term_A);
  disconnect_socket(term_B);

  
}