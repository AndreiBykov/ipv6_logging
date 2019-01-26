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
}
