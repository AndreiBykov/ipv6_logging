#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>

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

const int ETH_HLEN = 14;
const int IPV6_ADDR_SHIFT = 8;
const int IPV6_ADDR_LEN = 16;

void printIPv6Address(unsigned char* buf, int start_address_byte) {
    for (int i = start_address_byte; i < start_address_byte + IPV6_ADDR_LEN; i += 2) {
        std::cout << (int)buf[i] * 256 + (int)buf[i + 1];
        if (i + 2 < start_address_byte + IPV6_ADDR_LEN) {
            std::cout << ":";
        }
    }
}

int main(int argc, char* argv[]) {

    std::cout << "USAGE: "<< argv[0] << " [-i <if_name>]" << std::endl;

    std::string interface = "eth0";

    if (argc == 3 && strcmp(argv[1], "-i") == 0) {
        interface = argv[2];
    }

    std::cout << "interface = " << interface << std::endl;

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

    int sock = bpf_open_raw_sock(interface.c_str());

    if (bpf_attach_socket(sock, prog_fd) != 0){
        std::cerr << "Error creating socket" << std::endl;
        return 1;
    }

    std::cout << "Socket attached" << std::endl;

    unsigned char *buf = new unsigned char[2048];
    long size;
    while (true) {
        size = read(sock, buf, 2048);
        if(size != -1) {
            std::cout << std::hex << "Src host: ";
            printIPv6Address(buf, ETH_HLEN + IPV6_ADDR_SHIFT);

            std::cout << "     Dest host: ";
            printIPv6Address(buf, ETH_HLEN + IPV6_ADDR_SHIFT + IPV6_ADDR_LEN);

            std::cout << std::endl;
        }
    }
}
