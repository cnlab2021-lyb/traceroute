#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cassert>
#include <chrono>
#include <climits>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <utility>
#include <variant>
#include <vector>

namespace {

constexpr int kIpHeaderSize = 20;
constexpr int kIcmpIdentifier = 0x7122, kIcmpSeqNum = 0x1234;
constexpr uint16_t kInitialPort = 33435;

// Perform DNS lookup
in_addr LookUp(const char *domain) {
  hostent *host = gethostbyname(domain);
  if (!host || !host->h_addr_list) {
    std::cerr << "traceroute: unknown host " << domain << "\n";
    exit(1);
  }
  auto **addr_list = reinterpret_cast<in_addr **>(host->h_addr_list);
  if (!addr_list || !addr_list[0]) {
    std::cerr << "traceroute: unknown host " << domain << "\n";
    exit(1);
  }
  int num_ip = 0;
  while (addr_list[num_ip]) num_ip++;
  if (num_ip > 1) {
    std::cerr << "traceroute: Warning: " << domain
              << " has multiple addresses; using " << inet_ntoa(*addr_list[0])
              << "\n";
  }
  return *addr_list[0];
}

enum Mode { ICMP, TCP, UDP };

struct Config {
  Mode mode = UDP;
  int nqueries = 3;
  int first_ttl = 1;
  int max_ttl = 30;
  double wait_time = 5.0;
  char *hostname;
};

[[noreturn]] void PrintUsage() {
  std::cerr << "Usage:\n";
  std::cerr << "  traceroute [ -IT ] [ -f first_ttl ] [ -q nqueries ] [ -m "
               "max_ttl ] [ -w waittime ] host\n";
  exit(1);
}

[[noreturn]] void PrintError(const char *s = nullptr) {
  perror(s);
  exit(1);
}

Config ParseArg(int argc, char *argv[]) {
  Config config{};

  // NOLINTNEXTLINE
  auto ParseInt = [&]() {
    if (optind == argc) PrintUsage();
    try {
      return std::stoi(argv[optind++]);
    } catch (...) {
      PrintUsage();
    }
  };

  // NOLINTNEXTLINE
  auto ParseFloat = [&]() {
    if (optind == argc) PrintUsage();
    try {
      return std::stof(argv[optind++]);
    } catch (...) {
      PrintUsage();
    }
  };

  for (int opt = getopt(argc, argv, "fmqwIT"); opt != -1;
       opt = getopt(argc, argv, "fmqwIT")) {
    if (opt == 'I') config.mode = ICMP;
    if (opt == 'T') config.mode = TCP;

    if (opt == 'f') config.first_ttl = ParseInt();
    if (opt == 'm') config.max_ttl = ParseInt();
    if (opt == 'q') config.nqueries = ParseInt();
    if (opt == 'w') config.wait_time = ParseFloat();
  }

  if (optind != argc - 1) PrintUsage();
  config.hostname = argv[optind];
  return config;
}

namespace icmp {

// type
constexpr uint8_t kEchoReply = 0x0;
constexpr uint8_t kDestinationUnreachable = 0x3;
constexpr uint8_t kEchoRequest = 0x8;
constexpr uint8_t kTimeExceed = 11;

// code

// Destination unreachable
constexpr uint8_t kNetworkUnreachable = 0x0;
constexpr uint8_t kHostUnreachable = 0x1;
constexpr uint8_t kProtocolUnreachable = 0x2;
constexpr uint8_t kPortUnreachable = 0x3;

// Time exceeded
constexpr uint8_t kTTLExpired = 0x0;
constexpr uint8_t kFragmentReassemblyTimeExceeded = 0x1;

}  // namespace icmp

struct alignas(2) ICMPPacket {
  // type + code + checksum + identifier + seq
  static constexpr size_t kPacketSize = 8;

  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t sequence_number;

  ICMPPacket() = default;

  ICMPPacket(uint16_t id, uint16_t seq)
      : type(icmp::kEchoRequest),
        code(0x0),
        identifier(htons(id)),
        sequence_number(htons(seq)) {
    uint32_t sum = (static_cast<uint32_t>(type) << 8) + code + id + seq;
    auto high = static_cast<uint32_t>(sum >> 16);
    auto low = static_cast<uint32_t>(sum & ((1U << 16) - 1));
    checksum = htons(static_cast<uint16_t>(~(high + low)));
  }

  // Needs to be called if the object is directly built from bytes w/ memcpy
  void Normalize() {
    identifier = ntohs(identifier);
    sequence_number = ntohs(sequence_number);
  }
};

struct TCPHeader {
  uint16_t source_port;
  uint16_t destination_port;
  uint32_t sequence_number;
  uint32_t ack;
  uint32_t unused;
  uint16_t checksum;
  uint16_t urgent_pointer;
};

struct TCPPacket {};

struct UDPHeader {
  uint16_t source_port;
  uint16_t destination_port;
  uint16_t length;
  uint16_t checksum;
};

struct UDPPacket {};

using Packet = std::variant<ICMPPacket, TCPPacket, UDPPacket>;
using ClockType = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<ClockType>;

enum ICMPStatus : uint8_t {
  DESTINATION_REACHED,
  TIMEOUT,
  TTL_EXPIRED,
  HOST_UNREACHABLE,
  NETWORK_UNREACHABLE,
  PROTOCOL_UNREACHABLE,
};

class TraceRouteClient {
 protected:
  struct sockaddr_in addr_ {};  // NOLINT
  int send_fd_{}, recv_fd_{};   // NOLINT

  template <size_t BufferSize>
  bool RecvICMPReply(std::array<uint8_t, BufferSize> &buffer, ICMPPacket &recv,
                     struct sockaddr &recv_addr) const {
    socklen_t recv_addr_len = sizeof(recv_addr);
    auto recv_bytes = recvfrom(
        recv_fd_, reinterpret_cast<void *>(buffer.data()), buffer.size(), 0,
        reinterpret_cast<struct sockaddr *>(&recv_addr), &recv_addr_len);
    if (recv_bytes == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
      PrintError("recvfrom");
    }
    memcpy(&recv, buffer.data() + kIpHeaderSize, sizeof(recv));
    recv.identifier = ntohs(recv.identifier);
    recv.sequence_number = ntohs(recv.sequence_number);
    return false;
  }

 public:
  TraceRouteClient() = default;

  // XXX(wp): Probably implement these later?
  TraceRouteClient(const TraceRouteClient &other) = delete;
  TraceRouteClient(TraceRouteClient &&other) = delete;
  TraceRouteClient &operator=(const TraceRouteClient &other) = delete;
  TraceRouteClient &operator=(TraceRouteClient &&other) = delete;

  TraceRouteClient(char *host, int domain, int type, int protocol)
      : send_fd_(socket(domain, type, protocol)) {
    if (send_fd_ == -1) PrintError("socket");
    addr_.sin_family = AF_INET;
    addr_.sin_addr = LookUp(host);
    addr_.sin_port = htons(7);
    recv_fd_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  }

  virtual ~TraceRouteClient() = default;

  virtual void InitSocket(int ttl, double time_limit) {
    if (setsockopt(send_fd_, IPPROTO_IP, IP_TTL,
                   reinterpret_cast<const void *>(&ttl), sizeof(ttl)) < 0)
      PrintError("setsockopt(ttl)");
    struct timeval tv {};
    tv.tv_sec = static_cast<int>(time_limit);
    tv.tv_usec = static_cast<int>((time_limit - static_cast<int>(time_limit)) *
                                  1'000'000);
    if (setsockopt(recv_fd_, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const void *>(&tv), sizeof(tv)) < 0)
      PrintError("setsockopt(rcvtime)");
  }

  virtual void SendRequest(Packet packet) = 0;

  /// Return a tuple consisting of
  /// - Source IP address
  /// - Time when the packet is received
  /// - The returned status
  [[nodiscard]] virtual std::tuple<struct sockaddr, TimePoint, ICMPStatus>
  RecvReply() const = 0;

  const char *GetAddress() const { return inet_ntoa(addr_.sin_addr); }
};

class TCPClient : public TraceRouteClient {
  // XXX(wp): Fails with some routers if port is not 80
  uint16_t port_ = 80;
  int last_ret_ = INT_MIN;
  int fd_args_ = 0;
  TimePoint send_time_{};
  long time_limit_us_{};

 public:
  explicit TCPClient(char *host)
      : TraceRouteClient(host, AF_INET, SOCK_RAW, IPPROTO_ICMP) {}

  ~TCPClient() override {
    close(send_fd_);
    close(recv_fd_);
  }

  void InitSocket(int ttl, double time_limit) override {
    time_limit_us_ = static_cast<long>(time_limit * 1'000'000);
    close(send_fd_);
    send_fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    struct sockaddr bind_addr {};
    bind_addr.sa_family = AF_INET;
    if (bind(send_fd_, &bind_addr, sizeof(bind_addr)) < 0) PrintError("bind");
    if (setsockopt(send_fd_, IPPROTO_IP, IP_TTL,
                   reinterpret_cast<const void *>(&ttl), sizeof(ttl)) < 0)
      PrintError("setsockopt(ttl)");
    struct timeval tv {};
    tv.tv_sec = static_cast<int>(time_limit);
    tv.tv_usec = static_cast<int>((time_limit - static_cast<int>(time_limit)) *
                                  1'000'000);
    if (setsockopt(recv_fd_, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const void *>(&tv), sizeof(tv)) < 0)
      PrintError("setsockopt(rcvtime)");
    fd_args_ = fcntl(send_fd_, F_GETFL, NULL);
    if (fcntl(send_fd_, F_SETFL, fd_args_ | O_NONBLOCK) < 0) {
      PrintError("fnctl");
    }
  }

  void SendRequest(Packet packet) override {
    assert(std::holds_alternative<TCPPacket>(packet) &&
           "Expecting TCP packet.");
    addr_.sin_port = htons(port_);
    last_ret_ =
        connect(send_fd_, reinterpret_cast<const struct sockaddr *>(&addr_),
                sizeof(addr_));
    send_time_ = ClockType::now();
    if (last_ret_ != 0) {
      if (errno == EHOSTUNREACH || errno == ECONNREFUSED) {
        last_ret_ = errno;
      } else if (errno == EINPROGRESS) {
        last_ret_ = EALREADY;
      } else {
        PrintError("connect");
      }
    }
  }

  [[nodiscard]] std::tuple<struct sockaddr, TimePoint, ICMPStatus> RecvReply()
      const override {
    assert(last_ret_ != INT_MIN);
    std::array<uint8_t, kIpHeaderSize + ICMPPacket::kPacketSize + 64> buffer{};
    int last_ret{last_ret_};
    if (last_ret != EALREADY) {
      if (last_ret == EHOSTUNREACH) {
        return std::make_tuple(sockaddr{}, ClockType::now(), TIMEOUT);
      }
      struct sockaddr recv_addr {};
      memcpy(&recv_addr, &addr_, sizeof(recv_addr));
      return std::make_tuple(recv_addr, ClockType::now(), DESTINATION_REACHED);
    }
    while (true) {
      fd_set read_fds{}, write_fds{}, err_fds{};
      FD_ZERO(&read_fds);
      FD_ZERO(&write_fds);
      FD_ZERO(&err_fds);
      FD_SET(send_fd_, &read_fds);
      FD_SET(send_fd_, &write_fds);
      FD_SET(send_fd_, &err_fds);
      auto cur_time = ClockType::now();
      auto time_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                              cur_time - send_time_)
                              .count();
      if (time_elapsed > time_limit_us_) {
        return std::make_tuple(sockaddr{}, ClockType::now(), TIMEOUT);
      }
      timeval timeout_val{};
      timeout_val.tv_sec = (time_limit_us_ - time_elapsed) / 1'000'000;
      timeout_val.tv_usec = (time_limit_us_ - time_elapsed) % 1'000'000;
      if (select(send_fd_ + 1, &read_fds, &write_fds, &err_fds, &timeout_val) <
          0) {
        PrintError("select");
      }
      if (FD_ISSET(send_fd_, &read_fds) || FD_ISSET(send_fd_, &write_fds) ||
          FD_ISSET(send_fd_, &err_fds)) {
        last_ret =
            connect(send_fd_, reinterpret_cast<const struct sockaddr *>(&addr_),
                    sizeof(addr_));
        if (last_ret != 0) {
          last_ret = errno;
        }
        if (last_ret == 0 || last_ret == ECONNREFUSED) {
          struct sockaddr recv_addr {};
          memcpy(&recv_addr, &addr_, sizeof(recv_addr));
          return std::make_tuple(recv_addr, ClockType::now(),
                                 DESTINATION_REACHED);
        }
        if (last_ret != EALREADY) {
          ICMPPacket recv{};
          struct sockaddr recv_addr {};
          bool timeout = RecvICMPReply(buffer, recv, recv_addr);
          auto recv_time = ClockType::now();
          if (timeout) return std::make_tuple(sockaddr{}, recv_time, TIMEOUT);

          struct sockaddr_in send_addr {};
          socklen_t len = sizeof(send_addr);
          if (getsockname(send_fd_,
                          reinterpret_cast<struct sockaddr *>(&send_addr),
                          &len) < 0) {
            PrintError("getsockname");
          }

          uint16_t port = ntohs(send_addr.sin_port);
          TCPHeader header{};
          memcpy(&header,
                 buffer.data() + kIpHeaderSize + ICMPPacket::kPacketSize +
                     kIpHeaderSize,
                 sizeof(header));
          if (ntohs(header.source_port) != port) continue;
          if (recv.type == icmp::kTimeExceed) {
            return std::make_tuple(recv_addr, recv_time, TTL_EXPIRED);
          }
          if (recv.type == icmp::kDestinationUnreachable) {
            constexpr std::array<ICMPStatus, 4> kUnreachableLookUpTable = {
                NETWORK_UNREACHABLE, HOST_UNREACHABLE, PROTOCOL_UNREACHABLE,
                DESTINATION_REACHED};
            return std::make_tuple(recv_addr, recv_time,
                                   kUnreachableLookUpTable.at(recv.type));
          }
        } else {
          assert(false && "Unexpected last_ret.");
        }
      }
    }
  }
};

class ICMPClient : public TraceRouteClient {
 public:
  explicit ICMPClient(char *host)
      : TraceRouteClient(host, AF_INET, SOCK_RAW, IPPROTO_ICMP) {}

  // XXX(wp): Probably implement these later?
  ICMPClient(const ICMPClient &other) = delete;
  ICMPClient(ICMPClient &&other) = delete;
  ICMPClient &operator=(const ICMPClient &other) = delete;
  ICMPClient &operator=(ICMPClient &&other) = delete;

  ~ICMPClient() override {
    close(send_fd_);
    close(recv_fd_);
  }

  void SendRequest(Packet packet) override {
    assert(std::holds_alternative<ICMPPacket>(packet) &&
           "Expecting ICMP packet.");
    auto &icmp = std::get<ICMPPacket>(packet);
    if (sendto(send_fd_, reinterpret_cast<const void *>(&icmp), sizeof(icmp), 0,
               reinterpret_cast<const struct sockaddr *>(&addr_),
               sizeof(addr_)) < 0)
      PrintError("sendto");
  }

  [[nodiscard]] std::tuple<struct sockaddr, TimePoint, ICMPStatus> RecvReply()
      const override {
    std::array<uint8_t, kIpHeaderSize + ICMPPacket::kPacketSize + 64> buffer{};
    while (true) {
      ICMPPacket recv{};
      struct sockaddr recv_addr {};
      bool timeout = RecvICMPReply(buffer, recv, recv_addr);
      auto recv_time = ClockType::now();
      if (timeout) return std::make_tuple(sockaddr{}, recv_time, TIMEOUT);

      if (recv.identifier == kIcmpIdentifier &&
          recv.sequence_number == kIcmpSeqNum) {
        if (recv.type == icmp::kEchoReply) {
          return std::make_tuple(recv_addr, recv_time, DESTINATION_REACHED);
        }
      }
      if (recv.type == icmp::kTimeExceed) {
        ICMPPacket orig{};
        memcpy(&orig,
               buffer.data() + kIpHeaderSize + ICMPPacket::kPacketSize +
                   kIpHeaderSize,
               sizeof(orig));
        orig.identifier = ntohs(orig.identifier);
        orig.sequence_number = ntohs(orig.sequence_number);
        if (orig.identifier == kIcmpIdentifier &&
            orig.sequence_number == kIcmpSeqNum) {
          assert(recv.code == icmp::kTTLExpired);
          return std::make_tuple(recv_addr, recv_time, TTL_EXPIRED);
        }
      }
      if (recv.type == icmp::kDestinationUnreachable) {
        constexpr std::array<ICMPStatus, 4> kUnreachableLookUpTable = {
            NETWORK_UNREACHABLE, HOST_UNREACHABLE, PROTOCOL_UNREACHABLE,
            DESTINATION_REACHED};
        return std::make_tuple(recv_addr, recv_time,
                               kUnreachableLookUpTable.at(recv.type));
      }
    }
  }
};

class UDPClient : public TraceRouteClient {
  uint16_t port_ = kInitialPort;

 public:
  explicit UDPClient(char *host)
      : TraceRouteClient(host, AF_INET, SOCK_DGRAM, IPPROTO_UDP) {}

  ~UDPClient() {
    close(send_fd_);
    close(recv_fd_);
  }

  void SendRequest(Packet packet) override {
    assert(std::holds_alternative<UDPPacket>(packet) &&
           "Expecting UDP packet.");
    auto &udp = std::get<UDPPacket>(packet);
    addr_.sin_port = htons(port_);
    port_++;
    if (sendto(send_fd_, reinterpret_cast<const void *>(&udp), sizeof(udp), 0,
               reinterpret_cast<const struct sockaddr *>(&addr_),
               sizeof(addr_)) < 0)
      PrintError("sendto");
  }

  [[nodiscard]] std::tuple<struct sockaddr, TimePoint, ICMPStatus> RecvReply()
      const override {
    std::array<uint8_t, kIpHeaderSize + ICMPPacket::kPacketSize + 64> buffer{};
    while (true) {
      ICMPPacket recv{};
      struct sockaddr recv_addr {};
      bool timeout = RecvICMPReply(buffer, recv, recv_addr);
      auto recv_time = ClockType::now();
      if (timeout) return std::make_tuple(sockaddr{}, recv_time, TIMEOUT);

      UDPHeader header{};
      memcpy(&header,
             buffer.data() + kIpHeaderSize + ICMPPacket::kPacketSize +
                 kIpHeaderSize,
             sizeof(header));
      // Verify the returned UDP header by its destination port.
      if (ntohs(header.destination_port) != port_ - 1) continue;
      if (recv.type == icmp::kTimeExceed) {
        assert(recv.code == icmp::kTTLExpired);
        return std::make_tuple(recv_addr, recv_time, TTL_EXPIRED);
      }
      if (recv.type == icmp::kDestinationUnreachable) {
        constexpr std::array<ICMPStatus, 4> kUnreachableLookUpTable = {
            NETWORK_UNREACHABLE, HOST_UNREACHABLE, PROTOCOL_UNREACHABLE,
            DESTINATION_REACHED};
        return std::make_tuple(recv_addr, recv_time,
                               kUnreachableLookUpTable.at(recv.type));
      }
    }
  }
};

Packet BuildPacket(Mode mode) {
  switch (mode) {
    case TCP:
      return TCPPacket{};
    case UDP:
      return UDPPacket{};
    case ICMP:
      return ICMPPacket(kIcmpIdentifier, kIcmpSeqNum);
  }
  __builtin_unreachable();
}

std::unique_ptr<TraceRouteClient> BuildClient(const Config &config) {
  switch (config.mode) {
    case UDP:
      return std::make_unique<UDPClient>(config.hostname);
    case TCP:
      return std::make_unique<TCPClient>(config.hostname);
    case ICMP:
      return std::make_unique<ICMPClient>(config.hostname);
  }
  __builtin_unreachable();
}

bool operator!=(const struct sockaddr &lhs, const struct sockaddr &rhs) {
  return lhs.sa_family != rhs.sa_family ||
         memcmp(lhs.sa_data, rhs.sa_data, sizeof(lhs.sa_data));
}

class TraceRouteLogger {
  struct sockaddr previous_ip_ {};
  bool first_record_;

 public:
  explicit TraceRouteLogger(int ttl) : first_record_(true) {
    std::cout << std::setw(2) << ttl << " ";
    std::cout << std::flush;
  }
  ~TraceRouteLogger() { std::cout << "\n"; }

  void Print(struct sockaddr ip, const TimePoint &send_time,
             const TimePoint &recv_time, ICMPStatus status) {
    // First reply
    if (ip != previous_ip_ && status != TIMEOUT) {
      if (!first_record_) std::cout << "\n   ";
      char hostname[1024];
      getnameinfo(&ip, sizeof(ip), hostname, sizeof(hostname), nullptr, 0, 0);
      std::cout << hostname << " ("
                << inet_ntoa(reinterpret_cast<sockaddr_in *>(&ip)->sin_addr)
                << ")";
    }
    if (status == TIMEOUT) {
      std::cout << " *";
    } else if (status == HOST_UNREACHABLE) {
      std::cout << " !H";
    } else if (status == NETWORK_UNREACHABLE) {
      std::cout << " !N";
    } else if (status == PROTOCOL_UNREACHABLE) {
      std::cout << " !P";
    } else {
      auto time_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                              recv_time - send_time)
                              .count();
      std::cout << std::fixed << std::setprecision(3) << "  "
                << static_cast<double>(time_elapsed) / 1'000 << " ms";
      previous_ip_ = ip;
    }
    first_record_ = false;
    std::cout << std::flush;
  }
};

}  // namespace

int main(int argc, char *argv[]) {
  static_assert(sizeof(ICMPPacket) == ICMPPacket::kPacketSize,
                "Padding is not allowed.");
  auto config = ParseArg(argc, argv);

  std::unique_ptr<TraceRouteClient> client = BuildClient(config);
  std::cout << "traceroute to " << config.hostname << " ("
            << client->GetAddress() << "), " << config.max_ttl << " hops max"
            << std::endl;

  for (int hop = config.first_ttl; hop <= config.max_ttl; ++hop) {
    bool is_exceed = true;
    TraceRouteLogger logger(hop);
    // XXX(waynetu): (Improvement) Send all requests before receiving replies.
    for (int query = 0; query < config.nqueries; ++query) {
      client->InitSocket(hop, config.wait_time);
      auto send_time = ClockType::now();
      auto packet = BuildPacket(config.mode);
      client->SendRequest(packet);
      auto [source_ip, recv_time, status] = client->RecvReply();
      is_exceed &= (status != DESTINATION_REACHED);
      logger.Print(source_ip, send_time, recv_time, status);
    }

    // Destination reached
    if (!is_exceed) break;
  }
}
