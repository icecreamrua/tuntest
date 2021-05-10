#pragma once
#include <sys/ioctl.h>
#include </usr/include/net/if.h>
#include <assert.h>
#include <fcntl.h>
#include <cstring>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <iostream>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include </usr/include/net/if_packet.h>
#include <linux/net.h>
#include <netinet/ip_icmp.h>
#include <linux/route.h>
#include <unordered_set>
#include <linux/limits.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <err.h>
#include <time.h>
#include <openssl/err.h>
typedef struct msg
{
    uint16_t len;
    unsigned char message[255];
    unsigned char flag = 0;
} icmpmsg;
std::string get_currentPath();
void readIpTunList(std::unordered_set<std::string> &ipTunList);
void echoHelp();
int aes_encrypt(unsigned char *data, size_t datalen, const unsigned char *key, size_t keylen, unsigned char *encryteData);
int aes_decrypt(unsigned char *data, size_t datalen, const unsigned char *key, size_t keylen, unsigned char *decryteData);
unsigned char *rsa_encrypt(unsigned char *data, size_t datalen, const char *keyPath, unsigned char *encryptedData);
unsigned char *rsa_decrypt(unsigned char *data, size_t datalen, const char *keyPath, unsigned char *decryptedData);