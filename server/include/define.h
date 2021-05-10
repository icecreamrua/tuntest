#pragma once
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <iostream>
#include <sys/socket.h>
#include <string>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <err.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <utility>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <sys/ioctl.h>
#include </usr/include/net/if.h>
#include <assert.h>
#include <fcntl.h>
#include <cstring>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include </usr/include/net/if_packet.h>
#include <linux/net.h>
#include <linux/route.h>
#include <unordered_set>
#include <linux/limits.h>
#include <linux/if_tun.h>
#include <tins/tins.h>
#include <mutex>
#include <atomic>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#define max_client 10
using namespace std;
using namespace Tins;
#define tcpMaxbuf 4096
typedef struct msg
{
    uint16_t len;
    unsigned char message[tcpMaxbuf];
} icmpmsg;
typedef struct addrPort
{
    IPv4Address addr;
    uint16_t port;
    bool operator==(const addrPort &ap) const;
} addrPort;
struct hash_addrport
{
    size_t operator()(const addrPort &ap) const;
};
typedef struct addrPortFd
{
    IPv4Address addr;
    uint16_t port;
    int fd;
} addrPortFd;
unsigned short api_checksum16(unsigned short *buffer, int size);
typedef struct tcpPhdr
{
    in_addr srcaddr;
    in_addr dstaddr;
    unsigned char mbz;
    unsigned char protocol;
    uint16_t tcplen;
} tcpPhdr;
class spinLock
{
public:
    spinLock() = default;
    spinLock(const spinLock &) = delete;
    spinLock &operator=(const spinLock &) = delete;
    void lock();
    void unlock();

private:
    atomic_flag _flag = ATOMIC_FLAG_INIT;
};
std::string get_currentPath();
unsigned char *rsa_decrypt(unsigned char *data, size_t datalen,const char *keyPath, unsigned char *decryptedData);
unsigned char *rsa_encrypt(unsigned char *data, size_t datalen,const char *keyPath, unsigned char *encryptedData);
int aes_decrypt(unsigned char* data,size_t datalen,const unsigned char* key,size_t keylen,unsigned char* decryteData);
int aes_encrypt(unsigned char* data,size_t datalen,const unsigned char* key,size_t keylen,unsigned char* encryteData);