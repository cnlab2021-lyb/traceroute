#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <iostream>
#include <utility>

in_addr_t LookUp(const char *domain) {
  hostent *host = gethostbyname(domain);
  if (!host || !host->h_addr_list) {
    std::cerr << "traceroute: unknown host " << domain << "\n";
    exit(1);
  }
  in_addr **addr_list = reinterpret_cast<in_addr **>(host->h_addr_list);
  if (!addr_list || !addr_list[0]) {
    std::cerr << "traceroute: unknown host " << domain << "\n";
    exit(1);
  }
  return addr_list[0]->s_addr;
}

enum Mode { ICMP, TCP, UDP };

struct Config {
  Mode mode;
  int nqueries;
  char *hostname;
};

Config ParseArg(int argc, char *argv[]) {
  bool tcp = false, udp = false;
  Config config{};
  for (int opt = getopt(argc, argv, "qtu"); opt != -1;
       opt = getopt(argc, argv, "qtu")) {
    if (opt == 't') tcp = true;
    if (opt == 'u') udp = true;
    if (opt == 'q') config.nqueries = std::atoi(argv[optind++]);
  }

  if (tcp && udp) {
    std::cerr << "[Error] Cannot specify both TCP mode and UDP mode at the "
                 "same time.\n";
    exit(1);
  }

  if (optind != argc - 1) {
    std::cerr << "[Usage] traceroute [-q nqueries] [-t/-u] hostname\n";
    exit(1);
  }
  config.mode = (tcp ? TCP : (udp ? UDP : ICMP));
  config.hostname = argv[optind];
  return config;
}

struct ICMPPacket {
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

int main(int argc, char *argv[]) {
  auto config = ParseArg(argc, argv);

  struct sockaddr_in addr;
  addr.sin_port = htons(7);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = LookUp(config.hostname);

  constexpr int kMaxHop = 64;
  std::cout << "traceroute to " << config.hostname << " ("
            << inet_ntoa(addr.sin_addr) << "), " << kMaxHop << " hops max\n";

  for (int hop = 1; hop <= kMaxHop; ++hop) {
    for (int query = 0; query < config.nqueries; ++query) {
      // TODO: properly set up identifer and sequence number
      ICMPPacket request(0x7122, 0x1234);
      int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
      if (fd == -1) {
        perror("socket");
        exit(1);
      }

      // Set TTL
      if (setsockopt(fd, IPPROTO_IP, IP_TTL, reinterpret_cast<const void *>(&hop),
                     sizeof(hop)) == -1) {
        perror("setsockopt");
        exit(1);
      }

      if (sendto(fd, reinterpret_cast<const void *>(&request), sizeof(request), 0,
                 reinterpret_cast<const struct sockaddr *>(&addr),
                 sizeof(addr)) == -1) {
        perror("sendto");
        exit(1);
      }
    }
  }
  return 0;
}
