/*
 * Copyright (c) 2006  Dustin Sallings
 */

#ifndef MULTISNIFF_H
#define MULTISNIFF_H 1

#define FLAG_BIT(a)	(1<<a)
#define FLAG_PROMISC 0
#define FLAG_FLUSH 1

#define DEFAULT_CLEANUP_INTERVAL 5

#define FILENAME_MAXLEN 64

/* Maximum number of seconds we'll hold a pcap file open. */
#define DEFAULT_MAX_PKT_AGE 60

#define HASH_SIZE 637

struct cleanupConfig {
	int maxAge;
	int refreshTime;
};

void process(int flags, const char *intf,
	struct cleanupConfig conf, const char *outdir, char *filter);
char *ntoa(int);

/* This stuff was basically stolen from tcpdump */
#define ETHER_ADDR_LEN 6
struct ether_header {
	u_int8_t    ether_dhost[ETHER_ADDR_LEN];
	u_int8_t    ether_shost[ETHER_ADDR_LEN];
	u_int16_t   ether_type;
};

/* We primarily care about IP.  Everything else goes into a common bucket */
#define ETHERTYPE_IP 0x0800

#endif /* MULTISNIFF_H */
