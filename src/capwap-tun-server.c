#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_bridge.h>
#include <linux/sockios.h>
//#include "CWProtocol.h"

#define CW_DATA_PORT    5247
#define TUN_CTL_DEV     "/dev/net/tun"

int enable_debug = 0;
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
};

static void usage(void)
{
    fprintf(stderr, "capwap-tun-server [-d] -c <config>\n"
		    "\tconfig format:\n"
		    "\t<wtp_ip> <wtp_udp_port> <ifname> <br>\n"
		    "\twtp_ip: The IP address of WTP.\n"
		    "\twtp_udp_prot: The UDP port number of WTP "
		    "(use ANY for any port).\n"
		    "\tifname: Interface name of TAP interface.\n"
		    "\tbr: Bridge name to which ifname belong.\n");
}

static int get_tun_info_from_config(const char *config, 
        struct tun_info **tun_infos)
{
    FILE *fp = NULL;
    char buf[BUFSIZ];
    int i = 0, count = 0;
    struct tun_info *infos;
    char *pos, *tok, delim[] = " \t\n";

    *tun_infos = NULL;

    /* First pass to calculate the count of configuration */
    if ((fp = fopen(config, "r")) == NULL)
        goto fail;
    while (fgets(buf, BUFSIZ-1, fp) != (char *)NULL) {
        if (buf[0] == '#' || buf[0] == '\n')
            continue;
        count++;
    }
    
    /* Allocate memory */
    *tun_infos = (struct tun_info *)calloc(sizeof(struct tun_info), count);
    if ((infos = (*tun_infos)) == NULL)
        goto fail;

    /* Second pass */
    rewind(fp);
    while (fgets(buf, BUFSIZ-1, fp) != NULL) {
        if (buf[0] == '#' || buf[0] == '\n')
            continue;
        /* wtp_ip */
        if ((tok = strtok_r(buf, delim, &pos)) == NULL)
            goto fail;
        if ((infos[i].tun_addr.sin_addr.s_addr = inet_addr(tok)) == INADDR_NONE)
            goto fail;
        /* wtp_udp_port */
        if ((tok = strtok_r(NULL, delim, &pos)) == NULL)
            goto fail;
        infos[i].tun_addr.sin_port = (strcmp(tok,"ANY") ? htons(atoi(tok)) : 0);
        /* tun_if */
        if ((tok = strtok_r(NULL, delim, &pos)) == NULL)
            goto fail;
        strcpy(infos[i].tun_if, tok);
        /* tun_br */
        if ((tok = strtok_r(NULL, delim, &pos)) == NULL)
            goto fail;
        strcpy(infos[i].tun_br, tok);

        i++;
    }
    fclose(fp);
    return count;

fail:
    fclose(fp);
    if (*tun_infos)
        free(*tun_infos);
    return -1;
}

static void tap_rx(int fd, short type, void *arg)
{
}

static int get_tap_interface(char *ifname)
{
    int fd;
    struct ifreq ifr;

    /* Get file descriptor */
    if ((fd = open(TUN_CTL_DEV, O_RDWR)) < 0) {
        dbg_printf("Can't open " TUN_CTL_DEV "\n");
        return -1;
    }

    /* Create TAP interface */
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        dbg_printf("Can't set up TUN/TAP.\n");
	return -1;
    }
    strcpy(ifname, ifr.ifr_name);
    return fd;
}

static void revmoe_tap_interface(int fd)
{
    if (fd > 0)
        close(fd);
}

static int add_tap_to_bridge(char *ifname, char *br)
{
    int fd;
    struct ifreq ifr;

    /* Add into bridge */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, br, IFNAMSIZ);
    if ((ifr.ifr_ifindex = if_nametoindex(ifname)) == 0) {
        dbg_printf("Can't get index of interface %s.\n", ifname);
        close(fd);
        return -1;
    }
    if (ioctl(fd, SIOCBRADDIF, &ifr) < 0) {
        dbg_printf("Can't get add interface %s into bridge %s.\n", ifname, br);
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static void remove_from_bridge(char *ifname, char *br)
{
    int fd;
    struct ifreq ifr;

    /* Remove bridge member interface */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, br, IFNAMSIZ);
    ifr.ifr_ifindex = if_nametoindex(ifname);
    ioctl(fd, SIOCBRADDIF, &ifr);
    close(fd);
}

static int add_to_event_loop(struct tun_info *info)
{
    /* Add into event loop */
    event_set(&info->tun_ev, info->tun_fd, EV_READ|EV_PERSIST, tap_rx, info);
    event_add(&info->tun_ev, NULL);
}

static void remove_from_event_loop(struct tun_info *info)
{
    /* Clean event */
    if (event_initialized(&info->tun_ev) && 
            event_pending(&info->tun_ev, EV_READ, NULL))
        event_del(&info->tun_ev);
}

static int add_tap_interface(struct tun_info *infos, int tun_cnt)
{
    int i;

    for (i = 0; i < tun_cnt; i++) {
        struct tun_info *info = &infos[i];
        
        if (((info->tun_fd = get_tap_interface(info->tun_if)) < 0) || 
                (add_tap_to_bridge(info->tun_if, info->tun_br) < 0) || 
                (add_to_event_loop(info) < 0))
            goto fail;
    }
    return 0;

fail:
    while (i > 0) {
        struct tun_info *info = &infos[i];
        remove_from_event_loop(info);
        remove_from_bridge(info->tun_if, info->tun_br);
        revmoe_tap_interface(info->tun_fd);
        i--;
    }
    return -1;
}

int main(int argc, char *argv[])
{
    int opt, tun_cnt;
    const char *config;
    struct tun_info *tun_infos;

    while ((opt = getopt(argc, argv, "hdc:")) != -1) {
        switch (opt) {
            case 'c':
                config = optarg;
                break;
            case 'd':
                enable_debug = !!atoi(optarg);
                break;
            case 'h':
            default:
                usage();
                return 1;
        }
    }

    event_init();

    /* Read config */
    if ((tun_cnt = get_tun_info_from_config(config, &tun_infos)) <= 0) {
        dbg_printf("Can't parse config file: %s.\n", config);
        return 1;
    }

    /* Added interfaces */
    if (add_tap_interface(tun_infos, tun_cnt) < 0) {
        dbg_printf("Can't add TAP interfaces");
        free(tun_infos);
        return 1;
    }

    event_dispatch();

    return 0;
}
