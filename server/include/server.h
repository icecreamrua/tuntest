#pragma once
#include "define.h"
#include<atomic>
int open_tun(const char*);
int setTunAddr(const char *dev, const char *ipaddr, const char *mask);
int Initcpfd(int);
void tcpforward(int confd, int tunfd, IPv4Address cliaddr);
int tcptotun(msg *im, int tunfd, int sockfd,IPv4Address ciladdrNat);
int iniserver();