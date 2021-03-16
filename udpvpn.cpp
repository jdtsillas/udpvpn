//
// udpvpn.cpp
// ~~~~~~~~~~
//

#include <string>
#include <iostream>
#include <memory>
#include <functional>
#include <boost/ref.hpp>
#include <boost/asio.hpp>

#include <linux/if.h>
#include <linux/if_tun.h>

typedef std::function<void(boost::asio::streambuf&)> IoCompletion;

class TunnelDev {
 public:
  TunnelDev(boost::asio::io_service& io_service)
      : tunfd_(io_service, tun_alloc("tun1", IFF_TUN)),
        tapfd_(io_service, tun_alloc("tap1", IFF_TAP)) { }

  void Send(boost::asio::streambuf& buf) {
  }
  void Receive(IoCompletion completion) {
  }
  void Start(IoCompletion completion) {
  }

 private:
  int tun_alloc(std::string dev, int flags) {
    struct ifreq ifr;
    int fd, err;
    char name[IFNAMSIZ];
    
    strncpy(name, dev.c_str(), IFNAMSIZ);
    
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
      perror("Opening /dev/net/tun");
      return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
      perror("ioctl(TUNSETIFF)");
      close(fd);
      return err;
    }
    
    strcpy(name, ifr.ifr_name);
    std::cout << "Allocated " << name << " for " << dev << "\n";
    return fd;
  }

  boost::asio::posix::stream_descriptor tunfd_;
  boost::asio::posix::stream_descriptor tapfd_;
};

class UdpVpnServer {
 public:
  UdpVpnServer(boost::asio::io_service& io_service,
               const boost::asio::ip::udp::endpoint& remote,
               const boost::asio::ip::udp::endpoint& local)
      : send_socket_(io_service, boost::asio::ip::udp::v4()),
        remote_(remote),
        receive_socket_(io_service, local),
        tunnel_dev_(io_service) { }
  
  void Send(boost::asio::streambuf& buf) {
  }
  void Receive(IoCompletion completion) {
  }
  void Start() {
    tunnel_dev_.Start(
        [this](boost::asio::streambuf& buf) {
          Send(buf);
        });
    Receive(
        [this](boost::asio::streambuf& buf) {
          tunnel_dev_.Send(buf);
        });
  }

 private:
  boost::asio::ip::udp::socket send_socket_;
  boost::asio::ip::udp::endpoint remote_;
  boost::asio::ip::udp::socket receive_socket_;

  TunnelDev tunnel_dev_;
};

int main(int argc, char **argv) {
  boost::asio::io_service io_service;

  boost::asio::ip::udp::endpoint remote(
      boost::asio::ip::address::from_string("192.168.122.172"), 55555);
  boost::asio::ip::udp::endpoint local(
      boost::asio::ip::address::from_string("0.0.0.0"), 55555);
  UdpVpnServer udp_server(io_service, remote, local);

  udp_server.Start();
  
  io_service.run();
}
