/*
 * Copyright (c) 2006  Dustin Sallings
 * arch-tag: 28B08073-EF88-43EC-9962-3396B2DFCD09
 */

#ifndef MULTISNIFF_H
#define MULTISNIFF_H 1

#define FLAG_BIT(a)	(1<<a)
#define FLAG_PROMISC 0

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

#endif /* MULTISNIFF_H */
