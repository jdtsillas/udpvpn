//
// udpvpn.cpp
// ~~~~~~~~~~
//

#include <string>
#include <vector>
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
      : send_socket_(io_service, remote),
        receive_socket_(io_service, local) { }

  void Send(const IoBuffer& buf);
  void Receive(IoBuffer& buf);

 private:
  boost::asio::ip::udp::socket send_socket_;
  boost::asio::ip::udp::socket receive_socket_;
  std::vector<IoBuffer> receive_buffers_;
  std::vector<IoBuffer> send_buffers_;
};

class TunnelDev {
 public:
  TunnelDev(const std::string& tundev, const std::string& tapdev) {
  }

  void Send(const IoBuffer& buf);
  void Receive(const IoBuffer& buf);

 private:
  int tunfd_;
  int tapfd_;
  std::vector<IoBuffer> receive_buffers_;
  std::vector<IoBuffer> send_buffers_;
};

int main(int argc, char **argv) {
}
