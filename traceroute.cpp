#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cassert>
#include <chrono>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <utility>
#include <variant>
#include <vector>

namespace {

constexpr int kIpHeaderSize = 20;
constexpr int kIcmpIdentifier = 0x7122, kIcmpSeqNum = 0x1234;
constexpr int kTimeout = 5;

in_addr LookUp(const char *domain) {
  hostent *host = gethostbyname(domain);
  if (!host || !host->h_addr_list) {
    std::cerr << "traceroute: unknown host " << domain << "\n";
    exit(1);
  }
  auto **addr_list = reinterpret_cast<in_addr **>(host->h_addr_list);
  int num_ip = 0;
  if (!addr_list || !addr_list[0]) {
    std::cerr << "traceroute: unknown host " << domain << "\n";
    exit(1);
  }
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
  Mode mode = ICMP;
  int nqueries = 3;
  int first_ttl = 1;
  char *hostname;
};

[[noreturn]] void PrintUsage() {
  std::cerr << "Usage:\n";
  std::cerr << "  traceroute [ -f first_ttl ] [ -q nqueries ] [ -t/-u ] host\n";
  exit(1);
}

[[noreturn]] void PrintError(const char *s = nullptr) {
  perror(s);
  exit(1);
}

Config ParseArg(int argc, char *argv[]) {
  bool tcp = false, udp = false;
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

  for (int opt = getopt(argc, argv, "fqtu"); opt != -1;
       opt = getopt(argc, argv, "fqtu")) {
    if (opt == 't') tcp = true;
    if (opt == 'u') udp = true;

    if (opt == 'f') config.first_ttl = ParseInt();
    if (opt == 'q') config.nqueries = ParseInt();
  }

  if ((tcp && udp) || optind != argc - 1) PrintUsage();

  config.mode = (tcp ? TCP : (udp ? UDP : ICMP));
  config.hostname = argv[optind];
  return config;
}

struct alignas(2) ICMPPacket {
  static constexpr uint8_t kEchoReply = 0x0;
  static constexpr uint8_t kEchoRequest = 0x8;
  static constexpr uint8_t kTimeExceed = 11;

  // type + code + checksum + identifier + seq
  static constexpr size_t kPacketSize = 8;

  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t sequence_number;

  ICMPPacket() = default;

  ICMPPacket(uint16_t id, uint16_t seq)
      : type(kEchoRequest),
        code(0x0),
        identifier(htons(id)),
        sequence_number(htons(seq)) {
    uint32_t sum = (static_cast<uint32_t>(type) << 8) + code + id + seq;
    auto high = static_cast<uint32_t>(sum >> 16);
    auto low = static_cast<uint32_t>(sum & ((1U << 16) - 1));
    checksum = htons(static_cast<uint16_t>(~(high + low)));
  }
};

// TODO(waynetu): Implement TCP and UDP packets.
struct TCPPacket {};
struct UDPPacket {};

using Packet = std::variant<ICMPPacket, TCPPacket, UDPPacket>;
using ClockType = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<ClockType>;

class TraceRouteClient {
 protected:
  struct sockaddr_in addr_ {};  // NOLINT
  int fd_{};                    // NOLINT

 public:
  TraceRouteClient() = default;

  // XXX(wp): Probably implement these later?
  TraceRouteClient(const TraceRouteClient &other) = delete;
  TraceRouteClient(TraceRouteClient &&other) = delete;
  TraceRouteClient &operator=(const TraceRouteClient &other) = delete;
  TraceRouteClient &operator=(TraceRouteClient &&other) = delete;

  TraceRouteClient(char *host, int domain, int type, int protocol)
      : fd_(socket(domain, type, protocol)) {
    if (fd_ == -1) PrintError("socket");
    addr_.sin_port = htons(7);
    addr_.sin_family = AF_INET;
    addr_.sin_addr = LookUp(host);
  }

  virtual ~TraceRouteClient() = default;

  void InitSocket(int ttl) {
    if (setsockopt(fd_, IPPROTO_IP, IP_TTL,
                   reinterpret_cast<const void *>(&ttl), sizeof(ttl)) < 0)
      PrintError("setsockopt(ttl)");
    struct timeval tv;
    tv.tv_sec = kTimeout;
    tv.tv_usec = 0;
    if (setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const void *>(&tv), sizeof(tv)) < 0)
      PrintError("setsockopt(sendtime)");
  }

  virtual void SendRequest(Packet packet) = 0;

  /// Return a tuple consisting of
  /// - Source IP address
  /// - Time when the packet is received
  /// - Whether the ICMP packet is of type Time Exceeded
  /// - Whether the reply has timed out
  //
  // TODO(waynetu): Remove default implementation
  [[nodiscard]] virtual std::tuple<struct sockaddr, TimePoint, bool, bool>
  RecvReply() const {}

  const char *GetAddress() const { return inet_ntoa(addr_.sin_addr); }
};

class TCPClient : public TraceRouteClient {
 public:
  explicit TCPClient(char *host)
      : TraceRouteClient(host, AF_INET, SOCK_STREAM, 0) {}

  ~TCPClient() override { close(fd_); }

  void SendRequest(Packet packet) override {
    assert(std::holds_alternative<TCPPacket>(packet) &&
           "Expecting TCP packet.");
    if (connect(fd_, reinterpret_cast<const struct sockaddr *>(&addr_),
                sizeof(addr_)) < 0)
      PrintError("connect");
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

  ~ICMPClient() override { close(fd_); }

  void SendRequest(Packet packet) override {
    assert(std::holds_alternative<ICMPPacket>(packet) &&
           "Expecting ICMP packet.");
    auto &icmp = std::get<ICMPPacket>(packet);
    if (sendto(fd_, reinterpret_cast<const void *>(&icmp), sizeof(icmp), 0,
               reinterpret_cast<const struct sockaddr *>(&addr_),
               sizeof(addr_)) < 0)
      PrintError("sendto");
  }

  [[nodiscard]] std::tuple<struct sockaddr, TimePoint, bool, bool>
  RecvReply() const override {
    while (true) {
      std::array<char, kIpHeaderSize + ICMPPacket::kPacketSize + 64> buffer{};
      ICMPPacket recv{};
      struct sockaddr recv_addr {};
      socklen_t recv_addr_len = sizeof(recv_addr);
      auto recv_bytes = recvfrom(
          fd_, reinterpret_cast<void *>(buffer.data()), buffer.size(), 0,
          reinterpret_cast<struct sockaddr *>(&recv_addr), &recv_addr_len);
      auto recv_time = ClockType::now();
      if (recv_bytes == -1) {
        if (errno == EAGAIN)
          return std::make_tuple(sockaddr{}, recv_time, true, true);
        PrintError("recvfrom");
      }
      // Extract ICMP content
      memcpy(&recv, buffer.data() + kIpHeaderSize, sizeof(recv));
      recv.identifier = ntohs(recv.identifier);
      recv.sequence_number = ntohs(recv.sequence_number);
      // TODO(wp): Handle timeouts
      // TODO(wp): Handle replies other than ICMP echo
      if (recv.identifier == kIcmpIdentifier &&
          recv.sequence_number == kIcmpSeqNum) {
        if (recv.type == ICMPPacket::kEchoReply) {
          std::cerr << "GET!\n";
          return std::make_tuple(recv_addr, recv_time, false, false);
        }
      }
      if (recv.type == ICMPPacket::kTimeExceed) {
        ICMPPacket orig{};
        memcpy(&orig,
               buffer.data() + kIpHeaderSize + ICMPPacket::kPacketSize +
                   kIpHeaderSize,
               sizeof(orig));
        orig.identifier = ntohs(orig.identifier);
        orig.sequence_number = ntohs(orig.sequence_number);
        if (orig.identifier == kIcmpIdentifier &&
            orig.sequence_number == kIcmpSeqNum) {
          std::cerr << "Exceed!\n";
          return std::make_tuple(recv_addr, recv_time, true, false);
        }
      }
    }
  }
};

class UDPClient : public TraceRouteClient {
 public:
  explicit UDPClient(char *host)
      : TraceRouteClient(host, AF_INET, SOCK_DGRAM, 0) {}

  ~UDPClient() { close(fd_); }

  void SendRequest(Packet packet) override {
    assert(std::holds_alternative<UDPPacket>(packet) &&
           "Expecting UDP packet.");
    auto &udp = std::get<UDPPacket>(packet);
    if (sendto(fd_, reinterpret_cast<const void *>(&udp), sizeof(udp), 0,
               reinterpret_cast<const struct sockaddr *>(&addr_),
               sizeof(addr_)) < 0)
      PrintError("sendto");
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
  int ttl_;
  struct sockaddr previous_ip_;
  bool first_record_;

 public:
  explicit TraceRouteLogger(int ttl) : ttl_(ttl), first_record_(true) {}
  ~TraceRouteLogger() { std::cout << "\n"; }

  void Print(struct sockaddr ip, const TimePoint &send_time,
             const TimePoint &recv_time, bool timeout) {
    // First reply
    if (first_record_) std::cout << std::setw(2) << ttl_ << "  ";
    if (ip != previous_ip_ && !timeout) {
      if (!first_record_) std::cout << "\n    ";
      char hostname[30];
      getnameinfo(&ip, sizeof(ip), hostname, sizeof(hostname), nullptr, 0, 0);
      std::cout << hostname << " ("
                << inet_ntoa(reinterpret_cast<sockaddr_in *>(&ip)->sin_addr)
                << ")";
    }
    std::cout << "  ";
    if (timeout) {
      std::cout << "*";
    } else {
      auto time_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                              recv_time - send_time)
                              .count();
      std::cout << std::fixed << std::setprecision(3)
                << static_cast<double>(time_elapsed) / 1000 << " ms";
      previous_ip_ = ip;
    }
    first_record_ = false;
  }
};

}  // namespace

int main(int argc, char *argv[]) {
  static_assert(sizeof(ICMPPacket) == ICMPPacket::kPacketSize,
                "Padding is not allowed.");
  auto config = ParseArg(argc, argv);

  constexpr int kMaxHop = 64;
  std::unique_ptr<TraceRouteClient> client = BuildClient(config);
  std::cout << "traceroute to " << config.hostname << " ("
            << client->GetAddress() << "), " << kMaxHop << " hops max\n";

  for (int hop = config.first_ttl; hop <= kMaxHop; ++hop) {
    bool is_exceed = true;
    TraceRouteLogger logger(hop);
    // XXX(waynetu): (Improvement) Send all requests before receiving replies.
    for (int query = 0; query < config.nqueries; ++query) {
      // TODO(waynetu): properly set up identifer and sequence number
      client->InitSocket(hop);
      auto send_time = ClockType::now();
      auto packet = BuildPacket(config.mode);
      client->SendRequest(packet);
      auto [source_ip, recv_time, ex, timeout] = client->RecvReply();
      is_exceed &= ex;
      logger.Print(source_ip, send_time, recv_time, timeout);
    }

    // Destination reached
    if (!is_exceed) break;
  }
}
