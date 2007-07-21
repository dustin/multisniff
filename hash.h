/*
 * Copyright (c) 2006  Dustin Sallings
 */

#ifndef HASH_H
#define HASH_H 1

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <pcap.h>

struct hash_container {
	unsigned int key;
	char *filename;
	struct timeval last_addition;
	pcap_dumper_t *pcap_dumper;
	struct hash_container *next;
};

struct hash_keylist {
	int  nentries;
	int *entries;
};

struct hashtable {
	int     hashsize;
	struct hash_container *buckets[0];
};

struct hashtable *hash_init(int size);
struct hash_container *hash_store(struct hashtable *hash,
	pcap_t *pcap_thing, unsigned int key);
struct hash_container *hash_add(struct hashtable *hash, pcap_t *pcap_thing,
	unsigned int key, struct pcap_pkthdr *h, u_char *sp);
struct hash_container *hash_find(struct hashtable *hash, unsigned int key);
void    hash_delete(struct hashtable *hash, unsigned int key);
void    hash_destroy(struct hashtable *hash);
void    _hash_dump(struct hashtable *hash);
struct hash_keylist hash_keys(struct hashtable *hash);

#endif /* HASH_H */
