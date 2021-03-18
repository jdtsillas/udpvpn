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
#include <boost/program_options.hpp>
#include <boost/exception/diagnostic_information.hpp> 
#include <boost/exception_ptr.hpp>

#include <linux/if.h>
#include <linux/if_tun.h>

class UdpVpnServer {
 public:
  UdpVpnServer(boost::asio::io_service& io_service,
               const boost::asio::ip::udp::endpoint& remote,
               const boost::asio::ip::udp::endpoint& local,
               const std::string& tunnel)
      : send_socket_(io_service, boost::asio::ip::udp::v4()),
        remote_(remote),
        receive_socket_(io_service, local),
        tunfd_(io_service, tun_alloc(tunnel, IFF_TUN)) { }

  void Start() {
    if (tunfd_.is_open()) {
      TunReceive();
      UdpReceive();
    }
  }

  void TunReceive() {
    tunfd_.async_read_some(
        boost::asio::buffer(tunnel_buffer_, buf_max_len),
        [this](const boost::system::error_code& error,
               std::size_t bytes_transferred) {
          if (bytes_transferred) {
            send_socket_.async_send_to(
                boost::asio::buffer(tunnel_buffer_, bytes_transferred),
                remote_,
                [this](const boost::system::error_code& error,
                       std::size_t bytes_transferred) {
                  TunReceive();
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
          tunfd_.async_write_some(
              boost::asio::null_buffers(),
              [this](const boost::system::error_code& error,
                     std::size_t bytes_transferred) {
                std::size_t bytes_sent = tunfd_.write_some(
                    boost::asio::buffer(udp_buffer_, bytes_transferred));
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
    
    if ((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0 ) {
      perror("Opening /dev/net/tun");
      return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
      if (errno == EPERM) {
        std::cerr << "Insufficient priviledge to create or bind to a Tunnel Device.\n" <<
            "Try elevating the user to root access\n";
        close(fd);
        return err;
      }
      perror("ioctl(TUNSETIFF)");
      close(fd);
      return err;
    }

    strcpy(name, ifr.ifr_name);
    return fd;
  }

  static constexpr int buf_max_len = 1600;
  boost::array<char, buf_max_len> tunnel_buffer_;
  boost::array<char, buf_max_len> udp_buffer_;

  boost::asio::ip::udp::socket send_socket_;
  boost::asio::ip::udp::endpoint remote_;
  boost::asio::ip::udp::socket receive_socket_;
  boost::asio::ip::udp::endpoint from_endpoint_;

  boost::asio::posix::stream_descriptor tunfd_;
};

namespace po = boost::program_options;

bool decompose_ip_port(const std::string endpoint, std::string& ip, int& port) {
  int cpos = endpoint.find_first_of(':');
  if (cpos == std::string::npos) {
    return false;
  }
  ip = endpoint.substr(0, cpos);
  try {
    boost::asio::ip::address::from_string(ip);
    port = stoi(endpoint.substr(cpos + 1));
  } catch (...) { return false; }
  return true;
}

int main(int argc, char **argv) {
  std::string endpoint_local;
  std::string endpoint_remote;
  std::string tunnel_device;
  
  po::options_description description(
      "A program to implement a simple cleartext VPN tunnel over UDP");
  description.add_options()
      ("help", "Display this help message")
      ("local", po::value<std::string>(&endpoint_local)->required(),
       "(required) Local IP Address and port number for UDP packets (IP:UDPPort)")
      ("remote", po::value<std::string>(&endpoint_remote)->required(),
       "(required) Remote IP Address and port number for UDP packets (IP:UDPPort)")
      ("tunnel", po::value<std::string>(&tunnel_device)->default_value("tun1"),
       "Tunnel device name to use (default: tun1)");
  po::variables_map vm;
  
  po::store(
      po::parse_command_line(argc, argv, description), vm);
  
  try {
    po::notify(vm);
  } catch (...) {
    std::cout << description << "\n";
    return 1;
  }
    
  if (vm.count("help")) {
    std::cout << description << "\n";
    return 1;
  }

  std::string remote_ip;
  int remote_port;
  std::string local_ip;
  int local_port;

  if (!decompose_ip_port(endpoint_remote, remote_ip, remote_port) ||
      !decompose_ip_port(endpoint_local, local_ip, local_port)) {
    std::cout << "IP Address and port number must be in the form IP:UDPPort\n";
    return 1;
  }

  std::cout << "Remote: " << remote_ip << ":" << remote_port << "\n";
  std::cout << "Local: " << local_ip << ":" << local_port << "\n";
  std::cout << "Tunnel: " << tunnel_device << "\n";

  boost::asio::io_service io_service;

  boost::asio::ip::udp::endpoint remote(
      boost::asio::ip::address::from_string(remote_ip), remote_port);
  boost::asio::ip::udp::endpoint local(
      boost::asio::ip::address::from_string(local_ip), local_port);

  try {
    UdpVpnServer udp_server(io_service, remote, local, tunnel_device);
    udp_server.Start();
    io_service.run();
  } catch (const boost::exception& ex) {
    std::cout << "Boost exception: " << diagnostic_information(ex) << "\n";
    exit(1);
  }
}
