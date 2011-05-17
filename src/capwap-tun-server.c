#include "common.h"

int enable_debug = 0;

struct server_info {
    int srv_fd;
    struct sockaddr_in srv_addr;
    struct event srv_ev;
    struct {
	int tun_cnt;
	struct tun_info *tun_infos;
    } srv_tun;
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
    if (fp)
	fclose(fp);
    if (*tun_infos)
        free(*tun_infos);
    return -1;
}

static void tap_rx_cb(int fd, short type, void *arg)
{
    struct tun_info *tun = arg;
    struct server_info *srv = tun->tun_priv;
    ssize_t len;
    char buffer[L2_MAX_SIZE];

    if ((len = read(fd, buffer, L2_MAX_SIZE)) < 0) {
	dbg_printf("Can't read packet from TAP interface. (errno=%d)\n", len);
	return;
    }
    dbg_printf("Received %d bytes from TAP (%s)\n", len, tun->tun_if);

    if (tun->tun_alive && tun->tun_addr.sin_port) {
	if (sendto(srv->srv_fd, buffer, len, 0, 
		    (struct sockaddr *)&tun->tun_addr,
		    sizeof(struct sockaddr_in)) < 0) {
	    dbg_printf("Can't send packet to WTP.\n");
	    return;
	}
    } else {
	dbg_printf("WTP is not existed.\n");
    }
    return;
}

static void capwap_rx_cb(int fd, short type, void *arg)
{
    struct server_info *srv = arg;
    int len, i, tun_cnt = srv->srv_tun.tun_cnt;
    struct tun_info *infos = srv->srv_tun.tun_infos, *tun;
    char buffer[L2_MAX_SIZE];
    struct sockaddr_in client;
    int addrlen = sizeof(client);

    if ((len = recvfrom(fd, buffer, L2_MAX_SIZE, 0,
		    (struct sockaddr *)&client, &addrlen)) < 0) {
	dbg_printf("Can't recv packet from WTP.\n");
	return;
    }
    dbg_printf("Received %d bytes from WTP (%s).\n", len, 
	    inet_ntoa(client.sin_addr));

    for (i = 0; i < tun_cnt; i++) {
	tun = &infos[i];
	if (tun->tun_addr.sin_addr.s_addr == client.sin_addr.s_addr) {
	    tun->tun_alive = 1;
	    if (tun->tun_addr.sin_port == 0)
		tun->tun_addr.sin_port = client.sin_port;
	    if (tun->tun_addr.sin_port != client.sin_port) {
		dbg_printf("The port of WTP (%s) is changed from %d to %d.\n",
			inet_ntoa(client.sin_addr), 
			ntohs(tun->tun_addr.sin_port),
			ntohs(client.sin_port));
		tun->tun_addr.sin_port = client.sin_port;
	    }
	    if (write(tun->tun_fd, buffer, len) < len)
		dbg_printf("Can't write packet into TAP (%s).\n", tun->tun_if);
	    return;
	}
    }
    dbg_printf("Unknwon WTP (%s), ignored it.\n", 
	    inet_ntoa(client.sin_addr));
    return;
}

static int add_tap_interface(struct tun_info *infos, int tun_cnt, void *priv)
{
    int i;

    for (i = 0; i < tun_cnt; i++) {
        struct tun_info *info = &infos[i];
        
        if (((info->tun_fd = get_tap_interface(info->tun_if)) < 0) || 
                (add_tap_to_bridge(info->tun_if, info->tun_br) < 0) || 
                (add_to_event_loop(info, tap_rx_cb) < 0))
            goto fail;
	info->tun_priv = priv;
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
    struct server_info server_info, *srv_info;
    struct tun_info *tun_infos;

    srv_info = &server_info;
    memset(srv_info, 0, sizeof(struct server_info));

    while ((opt = getopt(argc, argv, "hdc:")) != -1) {
        switch (opt) {
            case 'c':
                config = optarg;
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

    event_init();

    /* Read config */
    if ((tun_cnt = get_tun_info_from_config(config, &tun_infos)) <= 0) {
        dbg_printf("Can't parse config file: %s.\n", config);
        return 1;
    }
    srv_info->srv_tun.tun_cnt = tun_cnt;
    srv_info->srv_tun.tun_infos = tun_infos;

    /* Added interfaces */
    if (add_tap_interface(tun_infos, tun_cnt, srv_info) < 0) {
        dbg_printf("Can't add TAP interfaces");
        free(tun_infos);
        return 1;
    }

    /* CAPWAP Data Channel */
    srv_info->srv_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (srv_info->srv_fd < 0) {
	dbg_printf("Can't create UDP socket.\n");
	return 1;
    }
    srv_info->srv_addr.sin_family = AF_INET;
    srv_info->srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srv_info->srv_addr.sin_port = htons(CW_DATA_PORT);
    if (bind(srv_info->srv_fd, (struct sockaddr *)&srv_info->srv_addr,
		sizeof(struct sockaddr_in)) < 0) {
	dbg_printf("Can't bind port %d.\n", CW_DATA_PORT);
	return -1;
    }
    event_set(&srv_info->srv_ev, srv_info->srv_fd, EV_READ|EV_PERSIST,
	    capwap_rx_cb, srv_info);
    event_add(&srv_info->srv_ev, NULL);

    event_dispatch();

    return 0;
}
