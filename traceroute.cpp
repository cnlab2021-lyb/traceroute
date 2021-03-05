#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>

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

int main(int argc, char *argv[]) {
  auto [mode, host] = ParseArg(argc, argv);

  struct sockaddr_in addr;
  addr.sin_port = htons(7);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = LookUp(host);

  constexpr int kMaxHop = 64;
  std::cout << "traceroute to " << host << " (" << inet_ntoa(addr.sin_addr)
            << "), " << kMaxHop << " hops max\n";

  for (int hop = 1; hop < kMaxHop; ++hop) {
  }
  return 0;
}
