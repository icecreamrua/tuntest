#include "../include/default.h"
using namespace std;
void echoHelp()
{
    cout<<"please assign the server ip address and the protocol port"<<endl;
    cout<<"option:"<<endl;
    cout<<"-i add the server ip address (IPv4 only)"<<endl;
    cout<<"-p add the protocol port (TCP)"<<endl;
    cout<<"-h echo the help message"<<endl;
    return;
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

//add proxy rule from local file 
void readIpTunList(unordered_set<string> &ipTunList)
{
    string txtname="rule.txt";
    txtname=get_currentPath()+txtname;
    char oneip[50];
    memset(oneip,0,50);
    auto filefd=fopen(txtname.c_str(),"r");
    if(!filefd)
    {
        filefd=fopen(txtname.c_str(),"w+");
        fclose(filefd);
        return;
    }
    while(fgets(oneip,50,filefd))
    {
        char str[INET_ADDRSTRLEN];
        string currentip=oneip;
        string setip;
        char **pptr;
        if(currentip.back()=='\n')
        {
            currentip.pop_back();
        }
        hostent * hptr;
        if((hptr=gethostbyname(currentip.c_str()))==nullptr)
        {
            continue;
        }
        if(hptr->h_addrtype==AF_INET)
        {
                pptr=hptr->h_addr_list;
                for(;*pptr!=nullptr;pptr++)
                {
                    setip=inet_ntop(hptr->h_addrtype,*pptr,str,sizeof(str));
                    ipTunList.insert(setip);
                }
        }
        memset(oneip,0,50);
    }
    return;
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
    if (RSA_private_decrypt(datalen, data, decryptedData, rsaKey, RSA_PKCS1_PADDING) == -1)
    {
        ERR_print_errors_fp(stdout);
        RSA_free(rsaKey);
        return nullptr;
    }
    fclose(keyFile);
    RSA_free(rsaKey);
    return decryptedData;
}


