#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <iostream>
#include <utility>
#include <vector>

constexpr int kBufSize = 16;

in_addr_t LookUp(const char *domain) {
  hostent *host = gethostbyname(domain);
  if (!host || !host->h_addr_list) {
    std::cerr << "traceroute: unknown host " << domain << "\n";
    exit(1);
  }
  in_addr **addr_list = reinterpret_cast<in_addr **>(host->h_addr_list);
  int num_ip = 0;
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

  auto ParseInt = [&]() {
    if (optind == argc) PrintUsage();
    try {
      return std::atoi(argv[optind++]);
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

  // type + code + checksum + identifier + seq
  static constexpr size_t kPacketSize = 8;

  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t sequence_number;

  ICMPPacket() = default;

  ICMPPacket(uint16_t identifier, uint16_t sequence_number)
      : type(kEchoRequest),
        code(0x0),
        identifier(htons(identifier)),
        sequence_number(htons(sequence_number)) {
    uint32_t sum = (static_cast<uint32_t>(type) << 8) + code + identifier +
                   sequence_number;
    uint16_t high = static_cast<uint16_t>(sum >> 16);
    uint16_t low = static_cast<uint16_t>(sum & ((1U << 16) - 1));
    checksum = htons(~(high + low));
  }
};

[[noreturn]] void PrintError(const char *s = nullptr) {
  perror(s);
  exit(1);
}

class TraceRouteClient {
 protected:
  struct sockaddr_in addr_;
  int fd_;

 public:
  TraceRouteClient() = default;

  TraceRouteClient(char *host, int domain, int type, int protocol)
      : fd_(socket(domain, type, protocol)) {
    if (fd_ == -1) PrintError("socket");
    addr_.sin_port = htons(7);
    addr_.sin_family = AF_INET;
    addr_.sin_addr.s_addr = LookUp(host);
  }

  ~TraceRouteClient() = default;

  virtual void InitSocket(int ttl) = 0;
  virtual void SendRequest(ICMPPacket packet) = 0;

  void RecvReply() {
    while (true) {
      std::array<char, kBufSize> buffer{};
      struct sockaddr_in recv_addr {};
      socklen_t recv_addr_len = sizeof(recv_addr);
      auto recv_bytes = recvfrom(
          fd_, reinterpret_cast<void *>(buffer.data()), kBufSize, 0,
          reinterpret_cast<struct sockaddr *>(&recv_addr), &recv_addr_len);
      if (recv_addr.sin_addr.s_addr == addr_.sin_addr.s_addr) {
        // TODO: Verify that identifier / sequence numbers are good
        // TODO: Measure time
        // TODO: Check TTL
        std::cerr << "GET!\n";
        break;
      }
    }
  }
};

class ICMPClient : public TraceRouteClient {
 public:
  ICMPClient(char *host)
      : TraceRouteClient(host, AF_INET, SOCK_RAW, IPPROTO_ICMP) {}

  ~ICMPClient() { close(fd_); }

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

int main(int argc, char *argv[]) {
  static_assert(sizeof(ICMPPacket) == 8, "Padding is not allowed.");
  auto config = ParseArg(argc, argv);

  constexpr int kMaxHop = 64;
  // std::cout << "traceroute to " << config.hostname << " ("
  //           << inet_ntoa(addr.sin_addr) << "), " << kMaxHop << " hops max\n";

  TraceRouteClient *client = new ICMPClient(config.hostname);
  for (int hop = config.first_ttl; hop <= kMaxHop; ++hop) {
    std::vector<std::chrono::time_point<std::chrono::system_clock>> send_time(
        config.nqueries);
    for (int query = 0; query < config.nqueries; ++query) {
      // TODO: properly set up identifer and sequence number
      ICMPPacket request(0x7122, 0x1234);
      client->InitSocket(hop);
      send_time[query] = std::chrono::system_clock::now();
      client->SendRequest(request);
      client->RecvReply();
    }
  }
  return 0;
}
