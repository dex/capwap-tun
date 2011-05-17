#ifndef _COMMON_H_

#define _COMMON_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <event.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_bridge.h>
#include <linux/sockios.h>

#define CW_DATA_PORT    5247
#define TUN_CTL_DEV     "/dev/net/tun"
#define L2_MAX_SIZE	1536

extern int enable_debug;

struct capwap_hdr {
	u_int32_t pad1;
	u_int32_t pad2;
} __attribute__((packed)); /* optional variable list */;
#define capwap_hdr_preamble(h)  ((ntohl((h)->pad1) >> 24) & 0xff)
#define capwap_hdr_hlen(h)  ((ntohl((h)->pad1) >> 19) & 0x1f)
#define capwap_hdr_wbid(h)  ((ntohl((h)->pad1) >> 9) & 0x1f)

#define dbg_printf(format, args...) 				\
    do { 							\
	if (enable_debug) { 					\
	    fprintf(stderr, "<DEBUG:%s:%d> " format, 		\
		    __FILE__, __LINE__, ##args); 		\
	} 							\
    } while(0)

struct tun_info {
    struct sockaddr_in tun_addr;
    /* TODO IPv6 */
    char tun_if[IFNAMSIZ];
    char tun_br[IFNAMSIZ];
    enum { TUN_DEAD = 0, TUN_ALIVE = 1 } tun_st;
    int tun_fd;
    struct event tun_ev;
    int tun_alive;
    void *tun_priv;
};


extern int get_tap_interface(char *ifname);
extern void revmoe_tap_interface(int fd);
extern int add_tap_to_bridge(char *ifname, char *br);
extern void remove_from_bridge(char *ifname, char *br);
extern int add_to_event_loop(struct tun_info *info, 
	void (*cb)(int, short, void*));
extern void remove_from_event_loop(struct tun_info *info);

#endif /* end of include guard: _COMMON_H_ */
