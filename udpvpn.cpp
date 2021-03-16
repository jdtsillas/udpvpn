//
// udpvpn.cpp
// ~~~~~~~~~~
//

#include <string>
#include <iostream>
#include <memory>
#include <functional>
#include <boost/array.hpp>
#include <boost/asio.hpp>

#include <linux/if.h>
#include <linux/if_tun.h>

class UdpVpnServer {
 public:
  UdpVpnServer(boost::asio::io_service& io_service,
               const boost::asio::ip::udp::endpoint& remote,
               const boost::asio::ip::udp::endpoint& local)
      : send_socket_(io_service, boost::asio::ip::udp::v4()),
        remote_(remote),
        receive_socket_(io_service, local),
        tapfd_(io_service, tun_alloc("tap1", IFF_TAP)) { }

  void Start() {
    TapReceive();
    UdpReceive();
  }

  void TapReceive() {
    tapfd_.async_read_some(
        boost::asio::null_buffers(),
        [this](const boost::system::error_code& error,
               std::size_t bytes_transferred) {
          std::size_t bytes_received = tapfd_.read_some(
              boost::asio::buffer(tunnel_buffer_, bytes_transferred));
          std::cout << "Read " << bytes_transferred <<
              " from tunfd: " << error << "\n";
          if (bytes_received) {
            send_socket_.async_send_to(
                boost::asio::buffer(tunnel_buffer_, bytes_received),
                remote_,
                [this](const boost::system::error_code& error,
                       std::size_t bytes_transferred) {
                  std::cout << "Wrote " << bytes_transferred <<
                      "to udp: " << error << "\n";
                  TapReceive();
                });
          }
        });
  }
  
  void UdpReceive() {
    receive_socket_.async_receive_from(
        boost::asio::buffer(udp_buffer_, buf_max_len),
        from_endpoint_,
        [this](const boost::system::error_code& error,
               std::size_t bytes_transferred) {
          tapfd_.async_write_some(
              boost::asio::null_buffers(),
              [this](const boost::system::error_code& error,
                     std::size_t bytes_transferred) {
                std::size_t bytes_sent = tapfd_.write_some(
                    boost::asio::buffer(udp_buffer_, bytes_transferred));
                std::cout << "Write " << bytes_sent << " to tapfd\n";
              });
          UdpReceive();
        });
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

  static constexpr int buf_max_len = 1600;
  boost::array<char, buf_max_len> tunnel_buffer_;
  boost::array<char, buf_max_len> udp_buffer_;

  boost::asio::ip::udp::socket send_socket_;
  boost::asio::ip::udp::endpoint remote_;
  boost::asio::ip::udp::socket receive_socket_;
  boost::asio::ip::udp::endpoint from_endpoint_;

  boost::asio::posix::stream_descriptor tapfd_;
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
