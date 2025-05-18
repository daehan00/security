#include <iostream>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_set>
#include <cstring>
#include <csignal>
#include <cstdlib>
#include <chrono>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>


std::unordered_set<std::string> blockedDomains;
bool trackPerformance = false;
std::chrono::steady_clock::duration classifyDuration;

void usage(const std::string& progName) {
    std::cout << "Usage: " << progName << " <site list file> [-t]\n"
              << "sample: " << progName << " top-1m.csv -t" << std::endl;
    std::exit(EXIT_FAILURE);
}

void loadBlocklist(const std::string& filename) {
    using namespace std::chrono;
    auto start = steady_clock::now();

    struct rusage before = {}, after = {};
    if (trackPerformance) getrusage(RUSAGE_SELF, &before);

    std::ifstream infile(filename);
    if (!infile.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        std::exit(EXIT_FAILURE);
    }

    std::string line;
    while (std::getline(infile, line)) {
        auto commaPos = line.find(',');
        if (commaPos == std::string::npos) continue;
        std::string domain = line.substr(commaPos + 1);
        blockedDomains.insert(domain);
    }
    infile.close();

    auto end = steady_clock::now();
    std::cout << "[+] Loaded " << blockedDomains.size() << " blocked domains." << std::endl;

    if (trackPerformance) {
        getrusage(RUSAGE_SELF, &after);
        auto ms = duration_cast<milliseconds>(end - start).count();
        long mem_kb = after.ru_maxrss - before.ru_maxrss;
        std::cout << "[T] Blocklist load time: " << ms << " ms\n";
        std::cout << "[T] Memory usage: " << mem_kb << " KB\n";
    }
}

bool isBlockedDomain(std::string_view host) {
    if (!trackPerformance)
        return blockedDomains.find(std::string(host)) != blockedDomains.end();

    auto start = std::chrono::steady_clock::now();
    bool result = blockedDomains.find(std::string(host)) != blockedDomains.end();
    auto end = std::chrono::steady_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    std::cout << "    Classification time: " << duration << " ns"<< std::endl;

    return result;
}

bool extractHostFromPayload(unsigned char* payload, int len, std::string_view& hostView) {
    auto* ip = reinterpret_cast<iphdr*>(payload);
    if (ip->protocol != IPPROTO_TCP) return false;

    int ipHeaderLen = ip->ihl * 4;
    auto* tcp = reinterpret_cast<tcphdr*>(payload + ipHeaderLen);
    int tcpHeaderLen = tcp->doff * 4;

    unsigned char* httpData = payload + ipHeaderLen + tcpHeaderLen;
    int httpLen = len - ipHeaderLen - tcpHeaderLen;
    if (httpLen <= 0) return false;

    const char* needle = "Host: ";
    unsigned char* hostStart = static_cast<unsigned char*>(
        memmem(httpData, httpLen, needle, std::strlen(needle)));
    if (!hostStart) return false;

    hostStart += std::strlen(needle);
    size_t remainingLen = httpData + httpLen - hostStart;
    unsigned char* hostEnd = static_cast<unsigned char*>(
        std::memchr(hostStart, '\n', remainingLen));
    if (!hostEnd) hostEnd = httpData + httpLen;

    int hostLen = hostEnd - hostStart;
    if (hostLen <= 0 || hostLen >= 256) return false;

    hostView = std::string_view(reinterpret_cast<char*>(hostStart), hostLen);
    while (!hostView.empty() && (hostView.back() == '\r' || hostView.back() == '\n')) {
        hostView.remove_suffix(1);
    }

    return true;
}

static int packetCallback(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfa, void*) {
    unsigned char* payload = nullptr;
    int len = nfq_get_payload(nfa, &payload);

    auto* ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t id = ph ? ntohl(ph->packet_id) : 0;

    if (len < 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

    std::string_view host;
    if (extractHostFromPayload(payload, len, host)) {
        if (isBlockedDomain(host)) {
            std::cout << ">>> Request to <" << host << "> Blocked." << std::endl;
            return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

int main(int argc, char* argv[]) {
    if (argc < 2) usage(argv[0]);

    std::string filename;

    if (argc == 2) {
        filename = argv[1];
    } else if (argc == 3 && std::string(argv[2]) == "-t") {
        trackPerformance = true;
        filename = argv[1];
    } else {
        usage(argv[0]);
    }

    loadBlocklist(filename);

    struct nfq_handle* h = nfq_open();
    if (!h) {
        std::cerr << "error during nfq_open()" << std::endl;
        return EXIT_FAILURE;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        std::cerr << "error during nfq_unbind_pf()" << std::endl;
        return EXIT_FAILURE;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        std::cerr << "error during nfq_bind_pf()" << std::endl;
        return EXIT_FAILURE;
    }

    struct nfq_q_handle* qh = nfq_create_queue(h, 0, &packetCallback, nullptr);
    if (!qh) {
        std::cerr << "error during nfq_create_queue()" << std::endl;
        return EXIT_FAILURE;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "can't set packet_copy mode" << std::endl;
        return EXIT_FAILURE;
    }

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));
    int rv;

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}

