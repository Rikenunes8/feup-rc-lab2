#pragma once

#define MAX_CMD_SIZE  128
#define MAX_RESP_SIZE 1024

#define RESP_WELCOME    220
#define RESP_SPEC_PASS  331
#define RESP_SUC_LOGIN  230
#define RESP_PASV_MODE  227
#define RESP_BIN_MODE   150
#define RESP_TRSF_COMP  226

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


int get_port(char* protocol);
int parse_args(struct args_t* args, int argc, char** argv);
int connect_socket(char* addr, int port);
int disconnect_socket(int sockfd);
int hostname_to_IP(char* hostname, char* ip);
int ftp_send_cmd(int socket, char* cmd);
int ftp_recv_resp(int socket, char* buffer, int len);
int download_file(int socket, char* filename);
