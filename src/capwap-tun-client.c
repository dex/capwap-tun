#include "common.h"

int enable_debug = 0;

struct client_info {
    int cli_fd;
    struct event cli_ev;
    struct tun_info cli_tun;
};

static void usage(void)
{
    fprintf(stderr, 
	    "capwap-tun-client [-d] -c <ac_ip> -t <tun_if> -b <br_if>\n");
}

static void tap_rx_cb(int fd, short type, void *arg)
{
    struct tun_info *tun = arg;
    struct client_info *cli = tun->tun_priv;
    ssize_t len;
    char buffer[L2_MAX_SIZE];
    const int capwap_hdrlen = sizeof(struct capwap_hdr);
    const unsigned char capwap_hdr[] = { 
	0x00, 0x10, 0x02, 0x00, 
	0x00, 0x00, 0x00, 0x00
    };

    /* Reserved space for CAPWAP header */
    if ((len = read(fd, buffer+capwap_hdrlen, L2_MAX_SIZE-capwap_hdrlen)) < 0) {
	dbg_printf("Can't read packet from TAP interface. (errno=%d)\n", len);
	return;
    }
    dbg_printf("Received %d bytes from TAP (%s)\n", len, tun->tun_if);

    /* Fill CAPWAP header */
    memcpy(buffer, capwap_hdr, capwap_hdrlen);

    if (tun->tun_alive) {
	if (sendto(cli->cli_fd, buffer, len+capwap_hdrlen, 0, 
		    (struct sockaddr *)&tun->tun_addr,
		    sizeof(struct sockaddr_in)) < 0) {
	    dbg_printf("Can't send packet to AC.\n");
	    return;
	}
    } else {
	dbg_printf("AC is not existed.\n");
    }
    return;
}

static void capwap_rx_cb(int fd, short type, void *arg)
{
    struct client_info *cli = arg;
    int len, i;
    struct tun_info *tun = &cli->cli_tun;
    char buffer[L2_MAX_SIZE];
    struct sockaddr_in server;
    int addrlen = sizeof(server);
    const int capwap_hdrlen = sizeof(struct capwap_hdr);

    if ((len = recvfrom(fd, buffer, L2_MAX_SIZE, 0,
		    (struct sockaddr *)&server, &addrlen)) < 0) {
	dbg_printf("Can't recv packet from AC.\n");
	return;
    }
    dbg_printf("Received %d bytes from AC (%s).\n", len, 
	    inet_ntoa(server.sin_addr));

    if (tun->tun_addr.sin_addr.s_addr == server.sin_addr.s_addr) {
        tun->tun_alive = 1;
        if (tun->tun_addr.sin_port != server.sin_port) {
            dbg_printf("The port of AC (%s) is invalid (%d).\n",
                    inet_ntoa(server.sin_addr), 
                    ntohs(server.sin_port));
        }
        /* Skip CAPWAP header */
        if (write(tun->tun_fd, buffer+capwap_hdrlen, len-capwap_hdrlen) < 
                len-capwap_hdrlen)
            dbg_printf("Can't write packet into TAP (%s).\n", tun->tun_if);
        return;
    }

    dbg_printf("Unknwon AC (%s), ignored it.\n", 
	    inet_ntoa(server.sin_addr));
    return;
}

int main(int argc, char *argv[])
{
    int opt;
    struct client_info client;
    struct tun_info *tun = &client.cli_tun;

    memset(&client, 0, sizeof(client));

    while ((opt = getopt(argc, argv, "dc:t:b:")) != -1) {
        switch (opt) {
            case 'c':
                tun->tun_addr.sin_addr.s_addr = inet_addr(optarg);
                if (tun->tun_addr.sin_addr.s_addr == INADDR_NONE) {
                    dbg_printf("Invalid IP address %s.\n", optarg);
                    return -1;
                }
                break;
            case 't':
                strncpy(tun->tun_if, optarg, IFNAMSIZ);
                tun->tun_if[IFNAMSIZ] = '\0';
                break;
            case 'b':
                strncpy(tun->tun_br, optarg, IFNAMSIZ);
                tun->tun_br[IFNAMSIZ] = '\0';
                break;
            case 'd':
                enable_debug = 1;
                break;
            case 'h':
            default:
                usage();
                return 1;
        }
    }

    if (!tun->tun_addr.sin_addr.s_addr || 
            !strlen(tun->tun_if) ||
            !strlen(tun->tun_br)) {
        usage();
        return 1;
    }

    event_init();

    /* Added interfaces */
    if (((tun->tun_fd = get_tap_interface(tun->tun_if)) < 0) || 
            (add_tap_to_bridge(tun->tun_if, tun->tun_br) < 0) || 
            (add_to_event_loop(tun, tap_rx_cb) < 0)) {
        dbg_printf("Can't set up TAP interface.\n");
        return 1;
    }
    tun->tun_priv = &client;
    tun->tun_alive = 1;

    /* CAPWAP Data Channel */
    client.cli_fd = socket(AF_INET, SOCK_DGRAM, 0);
    tun->tun_addr.sin_family = AF_INET;
    tun->tun_addr.sin_port = htons(CW_DATA_PORT);
    event_set(&client.cli_ev, client.cli_fd, EV_READ|EV_PERSIST,
            capwap_rx_cb, &client);
    event_add(&client.cli_ev, NULL);

    event_dispatch();
    return 0;
}
