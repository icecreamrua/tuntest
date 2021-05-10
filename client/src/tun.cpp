#include "../include/default.h"
#include "../include/tun.h"
#include "../include/rio_io.h"
#include <string>

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

int addroutrule(char *dev)
{
  readIpTunList(ipTunList);
  for (string oneip : ipTunList)
  {
    routadd(oneip.c_str(), dev);
  }
  return 0;
}

int routadd(const char *dst, char *dev)
{
  rtentry rte;
  sockaddr_in dst_addr, mask_addr;
  int err;
  memset(&rte, 0, sizeof(struct rtentry));
  memset(&dst_addr, 0, sizeof(struct sockaddr_in));
  memset(&mask_addr, 0, sizeof(struct sockaddr_in));
  dst_addr.sin_family = AF_INET;
  err = inet_pton(AF_INET, dst, &dst_addr.sin_addr);
  if (err < 0)
  {
    perror("Failed to set dstAddress");
    return -1;
  }
  mask_addr.sin_family = AF_INET;
  inet_pton(AF_INET, "255.255.255.255", &mask_addr.sin_addr);
  rte.rt_metric = 0;
  rte.rt_dst = *(struct sockaddr *)(&dst_addr);
  rte.rt_genmask = *(struct sockaddr *)(&mask_addr);
  rte.rt_dev = dev;
  rte.rt_flags = RTF_UP | RTF_HOST;
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
  {
    perror("Failed to create socket");
    return -1;
  }
  err = ioctl(sockfd, SIOCADDRT, &rte);
  if (err < 0)
  {
    perror("Failed to add route");
    close(sockfd);
    return -1;
  }
  close(sockfd);
  return 0;
}
int Inisendsockettcp(const char *dst, const char *port)
{
  addrinfo addr;
  addrinfo *getaddr;
  memset(&addr, 0, sizeof(addr));
  addr.ai_socktype = SOCK_STREAM;
  addr.ai_family = AF_INET;
  int err = getaddrinfo(dst, port, &addr, &getaddr);
  if (err != 0)
  {
    perror("Failed to getaddrinfo");
    return -1;
  }
  int sockfd = socket(getaddr->ai_family, getaddr->ai_socktype, getaddr->ai_protocol);
  if (sockfd < 0)
  {
    perror("Failed to set socket");
    return -1;
  }
  int ret = connect(sockfd, getaddr->ai_addr, getaddr->ai_addrlen);
  if (ret < 0)
  {
    perror("Failed to connect the server");
    return -1;
  }
  freeaddrinfo(getaddr);
  return sockfd;
}

int iniencrypt(char *serverip, int sockfd)
{
  int pid = getpid();
  time_t tm = time(nullptr);
  char temkey[20] = "0";
  sprintf(temkey, "%x%lx", pid, tm);
  if (!SHA256((unsigned char *)temkey, sizeof(temkey), aeskey))
  {
    return -1;
  }
  string rsaPublickey = get_currentPath() + "pubkey/" + serverip + ".pem";
  unsigned char sendData[256] = "0";
  if (!rsa_encrypt(aeskey, sizeof(aeskey), rsaPublickey.c_str(), sendData))
  {
    return -1;
  }
  rio_writen(sockfd, sendData, sizeof(sendData));
  cout << "send the key" << endl;
  rsa_decrypt(sendData, sizeof(sendData), "/home/vscode/.vscode/test/prikey.pem", aeskey);
  return 0;
}

int sendRecvTcp(int sockfd, int tunfd)
{
  unsigned char buftun[maxbuf];
  unsigned char bufsock[maxbuf];
  memset(buftun, 0, sizeof(buftun));
  int i = 0;
  int maxfd = 0;
  rio_t sockrp;
  rio_readinitb(&sockrp, sockfd);
  fd_set fdst;
  FD_ZERO(&fdst);
  for (;;)
  {
    FD_SET(sockfd, &fdst);
    FD_SET(tunfd, &fdst);
    maxfd = max(sockfd, tunfd) + 1;
    int no = select(maxfd, &fdst, nullptr, nullptr, nullptr);
    if (no < 0 && errno == EINTR)
      continue;
    if (no < 0)
    {
      perror("select error");
      exit(1);
    }
    if (FD_ISSET(tunfd, &fdst))
    {
      int ret;
      ret = read(tunfd, buftun, sizeof(buftun));
      if (ret < 0)
      {
        perror("Failed to read from tunfd");
        break;
      }
      unsigned char eth0ip[4];
      unsigned char destip[4];
      memcpy(eth0ip, &buftun[12], 4);
      memcpy(destip, &buftun[16], 4);
      char eth0ipp[16];
      char destipp[16];
      inet_ntop(AF_INET, eth0ip, eth0ipp, 16);
      inet_ntop(AF_INET, destip, destipp, 16);
      if (!ipTunList.count(string(destipp)))
      {
        continue;
      }
      ret = aes_encrypt(buftun, ret, aeskey, 32, bufsock + sizeof(uint16_t));
      uint16_t len = htons(ret);
      memcpy(bufsock, &len, sizeof(uint16_t));
      cout << ret << endl;
      ret = send(sockfd, bufsock, ret + sizeof(uint16_t), 0);
      if (ret < 0)
      {
        perror("Failed to send socket");
        return -1;
      }
      memset(bufsock, 0, maxbuf);
      memset(buftun, 0, maxbuf);
    }
    if (FD_ISSET(sockfd, &fdst))
    {
      uint16_t len;
      rio_readnb(&sockrp, bufsock, 2);
      len = ntohs(*(uint16_t *)&bufsock[0]);
      cout << "receve " << len << " bytes" << endl;
      int count = 0;
      while (count != len)
      {
        int n = rio_readnb(&sockrp, bufsock + count, len);
        count += n;
      }
      for (int i = 0; i < len; i++)
      {
        cout << (int)bufsock[i] << " ";
      }
      cout << endl;
      len = aes_decrypt(bufsock, len, aeskey, 32, buftun);
      int ret = rio_writen(tunfd, buftun, len);
      memset(bufsock, 0, maxbuf);
      memset(buftun, 0, maxbuf);
    }
  }
  return 0;
}

int main(int argc, char *argv[])
{
  int c;
  char *port = nullptr;
  char *serverip = nullptr;
  if (argc < 2)
  {
    echoHelp();
    exit(1);
  }
  while ((c = getopt(argc, argv, "p:i:h")) != -1)
  {
    switch (c)
    {
    case 'p':
      port = optarg;
      break;
    case 'i':
      serverip = optarg;
      break;
    case 'h':
      echoHelp();
      exit(0);
    default:
      echoHelp();
      break;
    }
  }
  if ((!port) || (!serverip))
  {
    echoHelp();
    exit(0);
  }
  readIpTunList(ipTunList);
  int tun;
  tun = open_tun(tunname);
  if (tun < 0)
  {
    perror("Failed to open the tun");
    return -1;
  }
  cout << "Tap name is " << tunname << endl;
  if (setTunAddr(tunname, tunip, subnetmask) < 0)
  {
    return -1;
  }
  addroutrule(tunname);
  int sendsockfd = Inisendsockettcp(serverip, port);
  if (sendsockfd < 0)
  {
    return -1;
  }
  if (iniencrypt(serverip, sendsockfd) < 0)
  {
    return -1;
  }
  if (sendRecvTcp(sendsockfd, tun) < 0)
  {
    return -1;
  }
  return 0;
}