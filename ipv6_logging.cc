#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/socket.h>
#include<netinet/ip6.h>

#include "bcc/BPF.h"

const std::string BPF_PROGRAM = R"(
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IPv6 0x86DD

int ipv6_filter(struct __sk_buff *skb) { 
	u8 *cursor = 0;	

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	
	if(ethernet->type != IPv6) {
	    	goto DROP;
	}

	KEEP:
		return -1;

	DROP:
		return 0;
})";

int main() {
    ebpf::BPF bpf;
    auto init_res = bpf.init(BPF_PROGRAM);

    if (init_res.code() != 0) {
        std::cerr << init_res.msg() << std::endl;
        return 1;
    }

    int prog_fd;
    auto load_res = bpf.load_func("ipv6_filter", BPF_PROG_TYPE_SOCKET_FILTER, prog_fd);

    if (load_res.code() != 0) {
        std::cerr << load_res.msg() << std::endl;
        return 1;
    }

    int sock = bpf_open_raw_sock("lo");

    if (bpf_attach_socket(sock, prog_fd) != 0){
        std::cerr << "Error creating socket" << std::endl;
        return 1;
    }

    unsigned char *buf = new unsigned char[2048];
    long size;
    while (true) {
        size = read(sock,buf, 2048);
        if(size != -1) {
            //  struct ip6_hdr *ip_packet = (struct ip6_hdr *) buf+14;

            struct in6_addr *src = (struct in6_addr *) &buf[22];
            struct in6_addr *dst = (struct in6_addr *) &buf[38];
            for(int i = 0; i < 8; i++)
                std::cout << src->__in6_u.__u6_addr16[i] << ".";
            std::cout << " - src " << std::endl;

            for(int i = 0; i < 8; i++)
                std::cout << dst->__in6_u.__u6_addr16[i] << ".";
            std::cout << " - dst" << std::endl;
            // for (int i = 0; i < size; i++) {
            //     std::cout << i << " : " << (int)buf[i] <<std::endl;
            // }
        }
    }

    std::cout << "Great!" << std::endl;
}
