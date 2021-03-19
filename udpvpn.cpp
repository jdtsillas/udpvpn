//
// udpvpn.cpp
// ~~~~~~~~~~
//

#include <string>
#include <iostream>
#include <fstream>
#include <memory>
#include <functional>
#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/exception/diagnostic_information.hpp> 
#include <boost/exception_ptr.hpp>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <linux/if.h>
#include <linux/if_tun.h>

// 256 bit key and 128 bit initial vector
static constexpr int symmetric_key_len = 256 / 8;
static constexpr int symmetric_iv_len = 128 / 8;

class UdpVpnServer {
 public:
  UdpVpnServer(boost::asio::io_service& io_service,
               const boost::asio::ip::udp::endpoint& remote,
               const boost::asio::ip::udp::endpoint& local,
               const std::string& tunnel,
               const unsigned char* key, const unsigned char* iv)
      : send_socket_(io_service, boost::asio::ip::udp::v4()),
        remote_(remote),
        receive_socket_(io_service, local),
        tunfd_(io_service, tun_alloc(tunnel, IFF_TUN)),
        key_(key), iv_(iv) {
    crypt_init();
  }

  ~UdpVpnServer() {
    if (rx_crypt_ctx_) {
      EVP_CIPHER_CTX_free(rx_crypt_ctx_);
    }
    if (tx_crypt_ctx_) {
      EVP_CIPHER_CTX_free(tx_crypt_ctx_);
    }
  }

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
            //std::cout << "Received Tunnel " << bytes_transferred << " bytes\n";
            boost::array<unsigned char, buf_max_len>* buffer_data;
            if (tx_crypt_ctx_) {
              bytes_transferred = encrypt(
                  tx_crypt_ctx_, tunnel_buffer_.data(), bytes_transferred,
                  encrypted_tunnel_buffer_.data());
              buffer_data = &encrypted_tunnel_buffer_;
            } else {
              buffer_data = &tunnel_buffer_;
            }
            send_socket_.async_send_to(
                boost::asio::buffer(*buffer_data, bytes_transferred),
                remote_,
                [this](const boost::system::error_code& error,
                       std::size_t bytes_transferred) {
                  //std::cout << "Sent UDP " << bytes_transferred << " bytes: " << error << "\n";
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
          if (bytes_transferred) {
            boost::array<unsigned char, buf_max_len>* buffer_data;
            //std::cout << "Received UDP " << bytes_transferred << " bytes\n";
            if (rx_crypt_ctx_) {
              bytes_transferred = decrypt(
                  rx_crypt_ctx_, udp_buffer_.data(), bytes_transferred,
                  plaintext_udp_buffer_.data());
              buffer_data = &plaintext_udp_buffer_;
            } else {
              buffer_data = &udp_buffer_;
            }
            tunfd_.async_write_some(
                boost::asio::buffer(*buffer_data, bytes_transferred),
                [this](const boost::system::error_code& error,
                       std::size_t bytes_transferred) {
                  //std::cout << "Sent Tunnel " << bytes_transferred << " bytes: " << error << "\n";
                  UdpReceive();
                });
          }
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

  struct CryptoException : std::exception {
    char const* what() const throw() {
      return "CryptoException";
    }
  };

  void crypt_init() {
    if (key_ == nullptr || iv_ == nullptr) {
      return;
    }

    /* Create and initialise the contexts */
    if (!(rx_crypt_ctx_ = EVP_CIPHER_CTX_new()))
      throw CryptoException();

    if (!(tx_crypt_ctx_ = EVP_CIPHER_CTX_new()))
      throw CryptoException();
  }

  int encrypt(EVP_CIPHER_CTX *ctx, const unsigned char *plaintext,
              int plaintext_len, unsigned char *ciphertext)
  {
    int len;
    int ciphertext_len;

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_, iv_)) {
      ERR_print_errors_fp(stderr);
      throw CryptoException();
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
      ERR_print_errors_fp(stderr);
      throw CryptoException();
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
      ERR_print_errors_fp(stderr);
      throw CryptoException();
    }
    ciphertext_len += len;

    return ciphertext_len;
  }

  int decrypt(EVP_CIPHER_CTX *ctx, const unsigned char *ciphertext,
              int ciphertext_len, unsigned char *plaintext)
  {
    int len;
    int plaintext_len;

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_, iv_)) {
      ERR_print_errors_fp(stderr);
      throw CryptoException();
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
      ERR_print_errors_fp(stderr);
      throw CryptoException();
    }
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
      ERR_print_errors_fp(stderr);
      throw CryptoException();
    }
    plaintext_len += len;

    return plaintext_len;
  }

  static constexpr int buf_max_len = 1600;
  boost::array<unsigned char, buf_max_len> tunnel_buffer_;
  boost::array<unsigned char, buf_max_len> encrypted_tunnel_buffer_;
  boost::array<unsigned char, buf_max_len> udp_buffer_;
  boost::array<unsigned char, buf_max_len> plaintext_udp_buffer_;

  boost::asio::ip::udp::socket send_socket_;
  boost::asio::ip::udp::endpoint remote_;
  boost::asio::ip::udp::socket receive_socket_;
  boost::asio::ip::udp::endpoint from_endpoint_;

  boost::asio::posix::stream_descriptor tunfd_;

  const unsigned char *key_;
  const unsigned char *iv_;
  EVP_CIPHER_CTX *rx_crypt_ctx_ = nullptr;
  EVP_CIPHER_CTX *tx_crypt_ctx_ = nullptr;
};

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

bool load_encryption_data(const std::string& key_file_path,
                          unsigned char* symmetric_key,
                          unsigned char* symmetric_iv) {
  std::ifstream key_file(key_file_path, std::ifstream::binary);

  key_file.read((char*)symmetric_key, symmetric_key_len);
  if (key_file.gcount() != symmetric_key_len) {
    return false;
  }
  key_file.read((char*)symmetric_iv, symmetric_iv_len);
  if (key_file.gcount() != symmetric_iv_len) {
    return false;
  }

  std::cout << "Loaded key data\n";
  return true;
}

namespace po = boost::program_options;

int main(int argc, char **argv) {
  std::string endpoint_local;
  std::string endpoint_remote;
  std::string tunnel_device;
  std::string key_file_path;
  
  po::options_description description(
      "A program to implement a simple VPN tunnel over UDP");
  description.add_options()
      ("help", "Display this help message")
      ("local", po::value<std::string>(&endpoint_local)->required(),
       "(required) Local IP Address and port number for UDP packets (IP:UDPPort)")
      ("remote", po::value<std::string>(&endpoint_remote)->required(),
       "(required) Remote IP Address and port number for UDP packets (IP:UDPPort)")
      ("tunnel", po::value<std::string>(&tunnel_device)->default_value("tun1"),
       "(optional) Tunnel device name to use (default: tun1)")
      ("key", po::value<std::string>(&key_file_path),
       "(optional) Key file to use for symmetric encryption (key file must contain a 256 bit binary key, followed by a 128 bit binary initial vector)");
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

  unsigned char symmetric_key[symmetric_key_len];
  unsigned char symmetric_iv[symmetric_iv_len];

  if (!key_file_path.empty()) {
    if (!load_encryption_data(key_file_path, symmetric_key, symmetric_iv)) {
      std::cout << "Unable to load key file from " << key_file_path << "\n";
      return 1;
    }
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
    UdpVpnServer udp_server(io_service, remote, local, tunnel_device,
                            !key_file_path.empty() ? symmetric_key : nullptr,
                            !key_file_path.empty() ? symmetric_iv : nullptr);
    udp_server.Start();
    io_service.run();
  } catch (const boost::exception& ex) {
    std::cout << "exception: " << diagnostic_information(ex) << "\n";
    exit(1);
  }
}
