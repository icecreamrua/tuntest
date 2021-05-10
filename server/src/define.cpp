#include "../include/define.h"
size_t hash_addrport::operator()(const addrPort &ap) const
{
    return hash<IPv4Address>()(ap.addr) ^ hash<uint16_t>()(ap.port);
}
bool addrPort::operator==(const addrPort &ap) const
{
    return addr == ap.addr && port == ap.port;
}
string get_currentPath()
{
    string path;
    char current_absolute_path[PATH_MAX];
    int cnt = readlink("/proc/self/exe", current_absolute_path, PATH_MAX);
    if (cnt < 0 || cnt >= PATH_MAX)
    {
        perror("Failed to get path");
        exit(-1);
    }
    int i;
    for (i = cnt; i >= 0; --i)
    {
        if (current_absolute_path[i] == '/')
        {
            current_absolute_path[i + 1] = '\0';
            break;
        }
    }
    path = current_absolute_path;
    return path;
}
unsigned short api_checksum16(unsigned short *buffer, int size)
{
    unsigned int cksum = 0;
    if (!buffer)
    {
        perror("NULL\n");
        return 0;
    }
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size)
    {
        cksum += *(unsigned char *)buffer;
    }
    /* 32 bit change to 16 bit */
    while (cksum >> 16)
    {
        cksum = (cksum >> 16) + (cksum & 0xFFFF);
    }
    return (unsigned short)(~cksum);
}
void spinLock::lock()
{
    while(_flag.test_and_set());
}
void spinLock::unlock()
{
    this->_flag.clear();
}
int aes_encrypt(unsigned char* data,size_t datalen,const unsigned char* key,size_t keylen,unsigned char* encryteData)
{
    AES_KEY aeskey;
    if(AES_set_encrypt_key(key,8*keylen,&aeskey))
    {
        ERR_print_errors_fp(stdout);
        return 0;
    }
    unsigned char tem[16]="0";
    int len=16-(datalen%16);
    len+=datalen;
    AES_cbc_encrypt(data,encryteData,len,&aeskey,tem,AES_ENCRYPT);
    return len;
}

int aes_decrypt(unsigned char* data,size_t datalen,const unsigned char* key,size_t keylen,unsigned char* decryteData)
{
    AES_KEY aeskey;
    if(AES_set_decrypt_key(key,8*keylen,&aeskey))
    {
        ERR_print_errors_fp(stdout);
        return 0;
    }
    unsigned char tem[16]="0";
    int len=datalen;
    AES_cbc_encrypt(data,decryteData,datalen,&aeskey,tem,AES_DECRYPT);
    for(int i=datalen-1;i>=0;i--)
    {
        if(decryteData[i]==0)
        {
            len--;
        }
        else
        return len;
    }
    return len;
}
unsigned char *rsa_encrypt(unsigned char *data, size_t datalen,const char *keyPath, unsigned char *encryptedData)
{
    FILE *keyFile = nullptr;
    if (!(keyFile = fopen(keyPath, "rb")))
    {
        perror("Faied to open the keyfile");
        return nullptr;
    }
    RSA *rsaKey = nullptr;
    if (!(rsaKey = PEM_read_RSA_PUBKEY(keyFile, nullptr, nullptr, nullptr)))
    {
        ERR_print_errors_fp(stdout);
        fclose(keyFile);
        return nullptr;
    }
    if (RSA_public_encrypt(datalen, data, encryptedData, rsaKey, RSA_PKCS1_PADDING) < 0)
    {
        ERR_print_errors_fp(stdout);
        RSA_free(rsaKey);
        return nullptr;
    }
    fclose(keyFile);
    RSA_free(rsaKey);
    return encryptedData;
}
unsigned char *rsa_decrypt(unsigned char *data, size_t datalen,const char *keyPath, unsigned char *decryptedData)
{
    FILE *keyFile = nullptr;
    if (!(keyFile = fopen(keyPath, "rb")))
    {
        perror("Faied to open the keyfile");
        return nullptr;
    }
    RSA *rsaKey = nullptr;
    if (!(rsaKey = PEM_read_RSAPrivateKey(keyFile, nullptr, nullptr, nullptr)))
    {
        ERR_print_errors_fp(stdout);
        fclose(keyFile);
        return nullptr;
    }
    if (RSA_private_decrypt(datalen, data, decryptedData, rsaKey, RSA_PKCS1_PADDING) <0)
    {
        ERR_print_errors_fp(stdout);
        RSA_free(rsaKey);
        return nullptr;
    }
    fclose(keyFile);
    RSA_free(rsaKey);
    return decryptedData;
}