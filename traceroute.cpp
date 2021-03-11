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
#include <iostream>
#include <memory>
#include <utility>
#include <vector>

namespace {

constexpr int kIpHeaderSize = 20;
constexpr int kIcmpIdentifier = 0x7122, kIcmpSeqNum = 0x1234;

in_addr_t LookUp(const char *domain) {
  hostent *host = gethostbyname(domain);
  if (!host || !host->h_addr_list) {
    std::cerr << "traceroute: unknown host " << domain << "\n";
    exit(1);
  }
  auto **addr_list = reinterpret_cast<in_addr **>(host->h_addr_list);
  int num_ip = 0;
  // cppcheck-suppress nullPointerRedundantCheck
  while (addr_list[num_ip]) num_ip++;
  if (!addr_list || !addr_list[0]) {
    std::cerr << "traceroute: unknown host " << domain << "\n";
    exit(1);
  }
  return addr_list[0]->s_addr;
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
    uint32_t sum = (static_cast<uint32_t>(type) << 8) + code + id +
                   seq;
    auto high = static_cast<uint32_t>(sum >> 16);
    auto low = static_cast<uint32_t>(sum & ((1U << 16) - 1));
    checksum = htons(static_cast<uint16_t>(~(high + low)));
  }
};

[[noreturn]] void PrintError(const char *s = nullptr) {
  perror(s);
  exit(1);
}

class TraceRouteClient {
 protected:
  struct sockaddr_in addr_{};  // NOLINT
  int fd_{};  // NOLINT

 public:
  TraceRouteClient() = default;

  // XXX(wp): Probably implement these later?
  TraceRouteClient(const TraceRouteClient &other) = delete;
  TraceRouteClient(TraceRouteClient &&other) = delete;
  TraceRouteClient& operator=(const TraceRouteClient &other) = delete;
  TraceRouteClient& operator=(TraceRouteClient &&other) = delete;

  TraceRouteClient(char *host, int domain, int type, int protocol)
      : fd_(socket(domain, type, protocol)) {
    if (fd_ == -1) PrintError("socket");
    addr_.sin_port = htons(7);
    addr_.sin_family = AF_INET;
    addr_.sin_addr.s_addr = LookUp(host);
  }

  virtual ~TraceRouteClient() = default;

  virtual void InitSocket(int ttl) = 0;
  virtual void SendRequest(ICMPPacket packet) = 0;

  [[nodiscard]]
  std::pair<std::chrono::time_point<std::chrono::steady_clock>, bool>
  RecvReply() const {
    while (true) {
      std::array<char, kIpHeaderSize + ICMPPacket::kPacketSize + 64> buffer{};
      ICMPPacket recv{};
      struct sockaddr_in recv_addr {};
      socklen_t recv_addr_len = sizeof(recv_addr);
      auto recv_bytes = recvfrom(
          fd_, reinterpret_cast<void *>(buffer.data()), buffer.size(), 0,
          reinterpret_cast<struct sockaddr *>(&recv_addr), &recv_addr_len);
      auto recv_time = std::chrono::steady_clock::now();
      if (recv_bytes == -1) {
        PrintError("recvfrom");
      }
      // Extract ICMP content
      memcpy(&recv, buffer.data() + kIpHeaderSize, sizeof(recv));
      recv.identifier = ntohs(recv.identifier);
      recv.sequence_number = ntohs(recv.sequence_number);
      // TODO(wp): Measure time
      if (recv.identifier == kIcmpIdentifier &&
          recv.sequence_number == kIcmpSeqNum) {
        if (recv.type == ICMPPacket::kEchoReply) {
          std::cerr << "GET!\n";
          return {recv_time, false};
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
          return {recv_time, true};
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
  ICMPClient& operator=(const ICMPClient &other) = delete;
  ICMPClient& operator=(ICMPClient &&other) = delete;

  ~ICMPClient() override { close(fd_); }

  void InitSocket(int ttl) override {
    if (setsockopt(fd_, IPPROTO_IP, IP_TTL,
                   reinterpret_cast<const void *>(&ttl), sizeof(ttl)) < 0)
      PrintError("setsockopt");
  }

  void SendRequest(ICMPPacket packet) override {
    if (sendto(fd_, reinterpret_cast<const void *>(&packet), sizeof(packet), 0,
               reinterpret_cast<const struct sockaddr *>(&addr_),
               sizeof(addr_)) < 0)
      PrintError("sendto");
  }
};

}  // namespace

int main(int argc, char *argv[]) {
  static_assert(sizeof(ICMPPacket) == ICMPPacket::kPacketSize,
                "Padding is not allowed.");
  auto config = ParseArg(argc, argv);

  constexpr int kMaxHop = 64;
  // std::cout << "traceroute to " << config.hostname << " ("
  //           << inet_ntoa(addr.sin_addr) << "), " << kMaxHop << " hops max\n";

  std::unique_ptr<TraceRouteClient> client =
      std::make_unique<ICMPClient>(config.hostname);
  for (int hop = config.first_ttl; hop <= kMaxHop; ++hop) {
    std::vector<std::chrono::time_point<std::chrono::steady_clock>> send_time(
        config.nqueries);
    std::vector<std::chrono::time_point<std::chrono::steady_clock>> recv_time(
        config.nqueries);
    bool is_exceed = true;
    for (int query = 0; query < config.nqueries; ++query) {
      // TODO(waynetu): properly set up identifer and sequence number
      ICMPPacket request(kIcmpIdentifier, kIcmpSeqNum);
      client->InitSocket(hop);
      send_time[query] = std::chrono::steady_clock::now();
      client->SendRequest(request);
      bool ex{};
      std::tie(recv_time[query], ex) = client->RecvReply();
      is_exceed &= ex;
    }

    if (!is_exceed) break;
  }
}
