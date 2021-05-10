#pragma once
#include <linux/if_tun.h>
int open_tun(const char*);
int setTunAddr(const char *,const char*,const char*);
int addroutrule(char*);
int routadd(const char*,char*);
int Inisendsockettcp(const char*,const char*);
int sendRecvTcp(int,int);