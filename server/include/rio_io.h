#pragma once
#include<iostream>
#include<unistd.h>
#include<utility>
#include<linux/types.h>
#include<fcntl.h>
#include<linux/stat.h>
#include<cstring>
#define RIO_BUFSIZE 8192
typedef struct
{
    int rio_fd;
    int rio_cnt;
    char* rio_bufptr;
    char rio_buf[RIO_BUFSIZE];
    /* data */
}rio_t;
void rio_readinitb(rio_t *rp,int fd);
ssize_t rio_read(rio_t* rp,char* usrbuf,size_t n);
ssize_t rio_readnb(rio_t *rp,void *usrbuf,size_t n);
ssize_t rio_readline(rio_t *rp,void* usrbuf,size_t maxlen);
ssize_t rio_readn(int fd,void *usrbuf,size_t n);
ssize_t rio_writen(int fd,void *usrbuf,size_t n);