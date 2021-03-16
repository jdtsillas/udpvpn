//
// udpvpn.cpp
// ~~~~~~~~~~
//

#include <string>
#include <vector>
#include <iostream>
#include <boost/asio.hpp>

#include <linux/if.h>
#include <linux/if_tun.h>

class IoBuffer {
};

class UdpServer {
 public:
  UdpServer(boost::asio::io_service& io_service,
            const boost::asio::ip::udp::endpoint& remote,
            const boost::asio::ip::udp::endpoint& local)
      : send_socket_(io_service, boost::asio::ip::udp::v4()),
        remote_(remote),
        receive_socket_(io_service, local) { }

  void Send(const IoBuffer& buf);
  void Receive(IoBuffer& buf);

 private:
  boost::asio::ip::udp::socket send_socket_;
  boost::asio::ip::udp::endpoint remote_;
  boost::asio::ip::udp::socket receive_socket_;
  std::vector<IoBuffer> receive_buffers_;
  std::vector<IoBuffer> send_buffers_;
};

class TunnelDev {
 public:
  TunnelDev() {
    char tun_name[IFNAMSIZ] = "tun1";
    char tap_name[IFNAMSIZ] = "tap1";
    tunfd_ = tun_alloc(tun_name, IFF_TUN);
    tapfd_ = tun_alloc(tap_name, IFF_TAP);
  }

  void Send(const IoBuffer& buf);
  void Receive(const IoBuffer& buf);

 private:
  int tun_alloc(char *dev, int flags) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
      perror("Opening /dev/net/tun");
      return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
      perror("ioctl(TUNSETIFF)");
      close(fd);
      return err;
    }

    strcpy(dev, ifr.ifr_name);
    std::cout << "Allocated " << dev << "\n";
    return fd;
  }

  int tunfd_;
  int tapfd_;
  std::vector<IoBuffer> receive_buffers_;
  std::vector<IoBuffer> send_buffers_;
};

int main(int argc, char **argv) {
  TunnelDev tunnel;

  boost::asio::io_service io_service;
  boost::asio::ip::udp::endpoint remote(
      boost::asio::ip::address::from_string("192.168.122.172"), 55555);
  boost::asio::ip::udp::endpoint local(
      boost::asio::ip::address::from_string("0.0.0.0"), 55555);

  UdpServer udp_server(io_service, remote, local);


}
