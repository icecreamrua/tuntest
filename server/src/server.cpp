#include "../include/readwrite.h"
#include "../include/server.h"
#include "../include/rio_io.h"
using namespace std;
using namespace Tins;
unordered_map<IPv4Address, unordered_map<addrPort, addrPortFd, hash_addrport> *> snat;
unordered_map<int, unsigned char[32]> aeskeymp;
const char subnetmask[] = "255,255,255,0";
const char tunip[] = "192.168.61.5";
const char tuniplist[] = "192.168.61.0";
const char subIP[] = "192.168.61.";
char tunname[] = "tunruarua";
string keypath;
int iniserver()
{
    string setTun("ip addr add ");
    setTun = setTun + tuniplist + "/24 dev " + tunname;
    system(setTun.c_str());
    setTun = "ip link set dev ";
    setTun = setTun + tunname + " up";
    system(setTun.c_str());
    system("ip link set dev tunruarua up");
    system("iptables -t nat -F");
    setTun = "iptables -t nat -A POSTROUTING -s ";
    setTun = setTun + tuniplist + "/24 -o eth0 -j MASQUERADE";
    system(setTun.c_str());
    system("echo \"1\" > /proc/sys/net/ipv4/ip_forward");
    int count = 1;
    for (; count <= max_client;)
    {
        string oneSubIP = subIP;
        char countA[10];
        sprintf(countA, "%d", count++);
        oneSubIP += countA;
        snat[IPv4Address(oneSubIP)] = nullptr;
    }
    return 0;
}
int open_tun(const char *dev)
{
    struct ifreq ifr;
    int fd;
    char device[] = "/dev/net/tun";
    if ((fd = open(device, O_RDWR)) < 0) //create file descriptor
    {
        perror("Failed to open TUN device:");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_NO_PI;
    ifr.ifr_flags |= IFF_TUN; //set dev type to tun
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    int err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err < 0)
    {

        perror("Failed to set TUN device name:");
        return -1;
    }
    return fd;
}

int setTunAddr(const char *dev, const char *ipaddr, const char *mask)
{
    sockaddr_in addr;
    memset(&addr, 0, sizeof(sockaddr));
    addr.sin_family = AF_INET;
    int err;
    err = inet_pton(AF_INET, ipaddr, &addr.sin_addr);
    if (err < 0)
    {
        perror("Failed to set TUN address");
        return -1;
    }
    ifreq ifr;
    memset(&ifr, 0, sizeof(ifreq));
    strncpy(ifr.ifr_name, dev, IF_NAMESIZE);
    memcpy(&ifr.ifr_addr, &addr, sizeof(sockaddr_in));
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {

        perror("Failed to create socket");
        return -1;
    }
    err = ioctl(sockfd, SIOCSIFADDR, &ifr);
    if (err < 0)
    {

        perror("Failed to set address");
        close(sockfd);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP;
    err = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
    if (err < 0)
    {

        perror("Failed to set TUN device up");
        close(sockfd);
        return -1;
    }
    memset(&addr, 0, sizeof(sockaddr_in));
    addr.sin_family = AF_INET;
    err = inet_pton(AF_INET, mask, &addr.sin_addr);
    if (err < 0)
    {

        close(sockfd);
        perror("Failed to set netmask");
        return -1;
    }
    memcpy(&ifr.ifr_netmask, &addr, sizeof(sockaddr_in));
    err = ioctl(sockfd, SIOCSIFNETMASK, &ifr);
    if (err < 0)
    {

        close(sockfd);
        perror("Failed to set TUN netmask");
        return -1;
    }
    close(sockfd);
    return 0;
}

int Initcpfd(int tunfd)
{
    int ret = 0;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Failed to get socket");
        return -1;
    }
    sockaddr_in selfaddr, cliaddr;
    selfaddr.sin_family = AF_INET;
    selfaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    selfaddr.sin_port = htons(2333);
    bind(sockfd, (sockaddr *)&selfaddr, sizeof(sockaddr));
    listen(sockfd, 10);
    socklen_t cliaddrlen;
    cout << "socket are readying" << endl;
    int countip = 1;
    for (;;)
    {
        int confd = accept(sockfd, (sockaddr *)&cliaddr, &cliaddrlen);
        auto stmap = new unordered_map<addrPort, addrPortFd, hash_addrport>;
        string oneSubIP = subIP;
        char countA[10];
        sprintf(countA, "%d", countip);
        countip++;
        if (countip > max_client)
            countip = 1;
        oneSubIP += countA;
        auto ciladdrNat = IPv4Address(oneSubIP);
        snat[ciladdrNat] = stmap;
        if (confd < 0)
        {
            perror("Failed to connect to client");
            return -1;
        }
        thread t = thread(tcpforward, confd, tunfd, ciladdrNat);
        t.detach();
    }
}
int getKey(int sockfd)
{
    int count = 0;
    unsigned char rsadata[256] = "0";
    unsigned char aeskey[32] = "0";
    while (count != 256)
    {
        int n = recv(sockfd, rsadata + count, 256 - count, 0);
        if (n <= 0)
        {
            return -1;
        }
        count += n;
    }
    if (!rsa_decrypt(rsadata, sizeof(rsadata), keypath.c_str(), aeskey))
    {
        return -1;
    }
    for (int i = 0; i <= 31; i++)
        aeskeymp[sockfd][i] = aeskey[i];
    return 0;
}
int tuntotcp(int tunfd)
{
    unsigned char buf[tcpMaxbuf];
    unsigned char data[tcpMaxbuf] = "0";
    int ret = read(tunfd, buf, sizeof(buf));
    if (ret < 0)
    {
        perror("Faied to read tun");
        exit(1);
    }
    if (buf[0] != 0x45)//not ipv4
        return 0;
    cout << "receve " << ret << " bytes from tun" << endl;
    RawPDU p((uint8_t *)buf, ret);
    IP msgip(p.to<IP>());
    cout << "IP Packet: " << msgip.src_addr() << "  -> " << msgip.dst_addr() << std::endl;
    auto mp = snat[IPv4Address(msgip.dst_addr())];
    addrPort srcaddr;
    srcaddr.addr = msgip.src_addr();
    addrPortFd dstaddr;
    srcaddr.port = 0;
    if (msgip.protocol() == IPPROTO_TCP)
    {
        TCP &msgtcp = msgip.rfind_pdu<TCP>();
        srcaddr.port = msgtcp.sport();
    }
    if (msgip.protocol() == IPPROTO_UDP)
    {
        UDP &msgudp = msgip.rfind_pdu<UDP>();
        srcaddr.port = msgudp.sport();
    }
    if ((*mp).count(srcaddr))
    {
        dstaddr = (*mp)[srcaddr];
        msgip.dst_addr(dstaddr.addr);
        PDU::serialization_type serval = msgip.serialize();
        uint16_t len = aes_encrypt((unsigned char *)serval.data(), serval.size(), aeskeymp[dstaddr.fd], 32, data + sizeof(uint16_t));
        cout<<len<<endl;
        auto netlen = htons(len);
        memcpy(data, &netlen, sizeof(uint16_t));
        ret = rio_writen(dstaddr.fd, data, len+sizeof(uint16_t));
        cout << "send " << len << "bytes to tcpsock" << endl;
    }
    return 0;
}
int tcptotun(msg *im, int tunfd, int sockfd, IPv4Address ciladdrNat)
{
    unsigned char data[tcpMaxbuf] = "0";
    im->len = aes_decrypt(im->message, im->len, aeskeymp[sockfd], 32, data);
    auto mp = snat[ciladdrNat];
    RawPDU p((uint8_t *)data, im->len);
    IP msgip(p.to<IP>());
    cout << "IP Packet: " << msgip.src_addr() << "  -> " << msgip.dst_addr() << std::endl;
    addrPort dstaddr;
    dstaddr.port = 0;
    addrPortFd srcaddr;
    srcaddr.port = 0;
    srcaddr.addr = msgip.src_addr();
    srcaddr.fd = sockfd;
    dstaddr.addr = msgip.dst_addr();
    if (msgip.protocol() == IPPROTO_TCP)
    {
        TCP &msgtcp = msgip.rfind_pdu<TCP>();
        srcaddr.port = msgtcp.sport();
        dstaddr.port = msgtcp.dport();
    }
    if (msgip.protocol() == IPPROTO_UDP)
    {
        UDP &msgudp = msgip.rfind_pdu<UDP>();
        srcaddr.port = msgudp.sport();
        dstaddr.port = msgudp.dport();
    }
    (*mp)[dstaddr] = srcaddr;
    msgip.src_addr(ciladdrNat);
    PDU::serialization_type serval = msgip.serialize();
    int ret = rio_writen(tunfd, serval.data(), serval.size());
    if (ret < 0)
    {
        perror(" ");
    }
    cout << "write " << ret << " bytes to tun" << endl;
    return 0;
}

void tcpforward(int confd, int tunfd, IPv4Address ciladdrNat)
{
    if (getKey(confd) < 0)
    {
        close(confd);
        cout << "close a socket" << endl;
        auto mp = snat[ciladdrNat];
        delete mp;
        return;
    }
    cout << "get the key" << endl;
    unsigned char data[tcpMaxbuf];
    int ret = 0;
    cout << "connected the client" << endl;
    int nleft = 0;
    icmpmsg *im = new icmpmsg;
    icmpmsg *ready = im;
    sockaddr_in clientAddr;
    socklen_t addrlen = 0;
    rio_t rp;
    rio_readinitb(&rp, confd);
    while ((ret = rio_readnb(&rp, data, 2)))
    {
        ready->len = ntohs(*(uint16_t *)&data[0]);
        int count = 0;
        while (count != ready->len)
        {
            int n = rio_readnb(&rp, data + count, ready->len - count);
            count += n;
        }
        memcpy(ready->message, data, ready->len);
        cout << "get " << ready->len << "char" << endl;
        tcptotun(ready, tunfd, confd, ciladdrNat);
        ready = new icmpmsg;
    }
    auto mp = snat[ciladdrNat];
    delete mp;
    cout << "close a socket" << endl;
    aeskeymp.erase(confd);
    close(confd);
    return;
}
int main()
{
    int tun;
    tun = open_tun(tunname);
    if (tun < 0)
    {
        return -1;
    }
    iniserver();
    keypath = get_currentPath() + "prikey.pem";
    int testfd = open(keypath.c_str(), O_RDONLY);
    if (testfd < 0)
    {
        perror("Failed to open the prikey");
        return -1;
    }
    close(testfd);
    thread tcplisten = thread(Initcpfd, tun);
    for (;;)
    {
        tuntotcp(tun);
    }
    tcplisten.join();
    return 0;
}