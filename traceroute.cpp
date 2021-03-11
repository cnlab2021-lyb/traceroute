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

std::pair<Mode, char *> ParseArg(int argc, char *argv[]) {
  bool tcp = false, udp = false;
  for (int opt = getopt(argc, argv, "tu"); opt != -1;
       opt = getopt(argc, argv, "tu")) {
    if (opt == 't') tcp = true;
    if (opt == 'u') udp = true;
  }

  if (tcp && udp) {
    std::cerr << "[Error] Cannot specify both TCP mode and UDP mode at the "
                 "same time.\n";
    exit(1);
  }

  if (optind != argc - 1) {
    std::cerr << "[Usage] traceroute [-t] [-u] hostname\n";
    exit(1);
  }
  Mode mode = (tcp ? TCP : (udp ? UDP : ICMP));
  return std::make_pair(mode, argv[optind]);
}

struct ICMPPacket {
  static constexpr uint8_t kEchoReply = 0x0;
  static constexpr uint8_t kEchoRequest = 0x8;

  static constexpr int kProtocol = 1;

  // type + code + checksum + identifier + seq
  static constexpr size_t kPacketSize = 8;

  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t identifier;
  uint16_t sequence_number;

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
  auto [mode, host] = ParseArg(argc, argv);

  struct sockaddr_in addr;
  addr.sin_port = htons(7122);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = LookUp(host);

  constexpr int kMaxHop = 1;
  std::cout << "traceroute to " << host << " (" << inet_ntoa(addr.sin_addr)
            << "), " << kMaxHop << " hops max\n";

  for (int hop = 0; hop < kMaxHop; ++hop) {
    // TODO: properly set up identifer and sequence number
    ICMPPacket packet(0x7122, 0x1234);
    int fd = socket(AF_INET, SOCK_RAW, ICMPPacket::kProtocol);
    if (fd == -1) {
      perror("socket");
      exit(1);
    }
    ssize_t sz =
        sendto(fd, reinterpret_cast<const void *>(&packet), sizeof(packet), 0,
               reinterpret_cast<const struct sockaddr *>(&addr), sizeof(addr));
    if (sz == -1) {
      perror("sendto");
      exit(1);
    }
  }
  return 0;
}
