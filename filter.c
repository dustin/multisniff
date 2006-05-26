/*
 * Copyright (c) 2006  dustin sallings
 * arch-tag: 4231F4E0-7F91-4370-B88B-03D9C794050A
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>
#include <assert.h>

#ifdef USE_PTHREAD
#include <pthread.h>
#endif /* USE_PTHREAD */

#include "mymalloc.h"
#include "multisniff.h"
#include "hash.h"

static pcap_t  *pcap_socket = NULL;
static int      dlt_len = 0;
static struct hashtable *hash=NULL;

static int shouldCleanup=0;
static int shuttingDown=0;

static void     filter_packet(u_char *, struct pcap_pkthdr *, u_char *);
static void     cleanup(int maxAge);
static void     signalShutdown(int);
static void     signalCleanup(int);
static char    *itoa(int in);

#ifdef USE_PTHREAD
# define lock(a)   pthread_mutex_lock(&(hash->mutexen[a]))
# define unlock(a) pthread_mutex_unlock(&(hash->mutexen[a]))
static pthread_cond_t threadcond;
static pthread_mutex_t threadmutex;
#else
# define lock(a)
# define unlock(a)
#endif

#ifdef USE_PTHREAD
void threadSleep(int howLong) {
	time_t now=time(NULL);
	struct timespec ts;

	ts.tv_nsec=0;
	ts.tv_sec=now + howLong;

	pthread_mutex_lock(&threadmutex);
	pthread_cond_timedwait(&threadcond, &threadmutex, &ts);
	pthread_mutex_unlock(&threadmutex);
}

static void *statusThread(void *data)
{
	struct cleanupConfig* conf=(struct cleanupConfig*)data;

	while(!shuttingDown) {

		threadSleep(conf->refreshTime);
		if(!shuttingDown) {
			cleanup(conf->maxAge);
		}
	}
	return NULL;
}
#else
void nonThreadsStats(struct cleanupConfig conf)
{
	static time_t last_time=0;
	time_t t=0;

	t=time(NULL);

	if(t-last_time > conf.refreshTime) {
		last_time=t;
		cleanup(conf.maxAge);
	}
}
#endif /* USE_PTHREAD */

#ifdef USE_PTHREAD
static void exitCleanup(pthread_t sp) {
	printf("Waiting for status printer thread.\n");
	pthread_mutex_lock(&threadmutex);
	pthread_cond_signal(&threadcond);
	pthread_mutex_unlock(&threadmutex);
	pthread_join(sp, NULL);
	printf("Joined status printer thread.\n");
#else
static void exitCleanup() {
#endif

	hash_destroy(hash);
	pcap_close(pcap_socket);
#ifdef MYMALLOC
	_mdebug_dump();
#endif /* MYMALLOC */
	exit(0);
}

static void setupSignals() {
	sigset_t sigBlockSet;
	struct sigaction saShutdown, saCleanup;

	sigemptyset(&sigBlockSet);
	sigaddset(&sigBlockSet, SIGHUP);
	if(sigprocmask(SIG_BLOCK, &sigBlockSet, NULL) < 0) {
		perror("sigprocmask");
		exit(1);
	}

	saShutdown.sa_handler=signalShutdown;
	saShutdown.sa_flags=0;
	sigemptyset(&saShutdown.sa_mask);

	if(sigaction(SIGINT, &saShutdown, NULL) < 0) {
		perror("sigaction(INT)");
		exit(1);
	}
	if(sigaction(SIGTERM, &saShutdown, NULL) < 0) {
		perror("sigaction(TERM)");
		exit(1);
	}

	saCleanup.sa_handler=signalCleanup;
	saCleanup.sa_flags=0;
	sigemptyset(&saShutdown.sa_mask);

	if(sigaction(SIGQUIT, &saCleanup, NULL) < 0) {
		perror("sigaction(QUIT)");
		exit(1);
	}
}

void
process(int flags, const char *intf, struct cleanupConfig conf,
	const char *outdir, char *filter)
{
	char            errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program prog;
	bpf_u_int32     netmask=0;
	int             flagdef;
#ifdef USE_PTHREAD
	pthread_t		sp;
#endif

	setupSignals();

	if (flags & FLAG_BIT(FLAG_PROMISC))	{
		flagdef = 1;
	} else {
		flagdef = 0;
	}

	pcap_socket = pcap_open_live(intf, 65535, flagdef, 10, errbuf);

	if (pcap_socket == NULL) {
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		exit(-1);
	}
	switch (pcap_datalink(pcap_socket)) {
	case DLT_EN10MB:
		dlt_len = 14;
		break;
	case DLT_SLIP:
		dlt_len = 16;
		break;
	case DLT_PPP:
		dlt_len = 4;
		break;
	case DLT_FDDI:
		fprintf(stderr, "Sorry, can't do FDDI\n");
		exit(1);
		break;
	default:
		dlt_len = 4;
	}

	if (pcap_compile(pcap_socket, &prog, filter, 1, netmask) < 0) {
		fprintf(stderr, "pcap_compile: %s\n", errbuf);
		exit(1);
	}
	if (pcap_setfilter(pcap_socket, &prog) < 0) {
		fprintf(stderr, "pcap_setfilter: %s\n", errbuf);
		exit(1);
	}

	hash=hash_init(637);

#ifdef USE_PTHREAD
	/* OK, create the status printer thread */
	if(pthread_mutex_init(&threadmutex, NULL) < 0) {
		perror("pthread_mutex_init");
		exit(1);
	}
	if(pthread_cond_init(&threadcond, NULL) < 0) {
		perror("pthread_cond_init");
		exit(1);
	}
	if(pthread_create(&sp, NULL, statusThread, &conf) < 0) {
		perror("pthread_create");
		exit(1);
	}
#endif /* USE_PTHREAD */

	fprintf(stderr,
		"interface: %s, filter: ``%s'', %spromiscuous, %sthreaded\n",
		intf, filter, (flags & FLAG_BIT(FLAG_PROMISC)) ? "" : "NOT ",
#ifdef USE_PTHREAD
		""
#else
		"NOT "
#endif
		);
	fflush(stderr);

	if(chdir(outdir) < 0) {
		perror("chdir");
		exit(1);
	}

	while (!shuttingDown) {
		pcap_loop(pcap_socket, 65535, (pcap_handler)filter_packet, NULL);
		if(shouldCleanup) {
			printf("# Cleaning up open pcap files\n");
			hash_destroy(hash);
			hash=hash_init(637);
			shouldCleanup=0;
		}
#ifdef USE_PTHREAD
		/* This is for bad pthread implementations */
		usleep(1);
#else
		nonThreadsStats(conf);
#endif /* USE_PTHREAD */
	}

#if USE_PTHREAD
	exitCleanup(sp);
#else
	exitCleanup();
#endif
}

static void
cleanup(int maxAge)
{
	static unsigned int last_pcount=0, last_dropcount=0;
	struct pcap_stat stats;
	struct hash_container *p;
	int i;
	struct timeval now;

	if(gettimeofday(&now, NULL) < 0) {
		perror("gettimeofday");
		exit(1);
	}

	if (pcap_stats(pcap_socket, &stats) == 0) {
		printf("# Processed %d packets, dropped %d\n",
		       stats.ps_recv-last_pcount,
			   stats.ps_drop-last_dropcount);
		last_pcount=stats.ps_recv;
		last_dropcount=stats.ps_drop;
	} else {
		printf("# Error getting pcap statistics.\n");
	}
	/* Look for anything old enough to get cleaned up */
	for(i=0; i<hash->hashsize; i++) {
		lock(i);
		p=hash->buckets[i];
		unlock(i);
		if(p) {
			int ci=0;
			int toClose[1024];
			int closeOffset=0;

			lock(i);
			for(; p; p=p->next) {
				pcap_dump_flush(p->pcap_dumper);
				if(p->last_addition.tv_sec + maxAge < now.tv_sec) {
					toClose[closeOffset++]=p->key;
				}
			}
			unlock(i);

			for(ci=0; ci<closeOffset; ci++) {
				p=hash_find(hash, toClose[ci]);
				assert(p != NULL);
				printf("# Closing %s (too old)\n", p->filename);
				p=NULL; /* Can't use this anymore */
				hash_delete(hash, toClose[ci]);
			}
		}
	}
}

/* this is the function that's called when pcap reads a packet */
void
filter_packet(u_char * u, struct pcap_pkthdr * p, u_char * packet)
{
#define IP_SIZE  20
#define TCP_SIZE 20

	unsigned short  ip_options = 0;
	struct ip      *ip;

	/* p->len should never be smaller than the smallest possible packet */
	if (p->len < (dlt_len + IP_SIZE + TCP_SIZE)) {
		fprintf(stderr, "! Skipping packet that's too small.\n");
		return;
	}

	/* cast an ip pointer */
	ip = (struct ip *) (packet + dlt_len);

	/* determine length of ip options (usually 0) */
	ip_options = ip->ip_hl;
	ip_options -= 5;
	ip_options *= 4;

	/* nuke any flags in the offset field */
	ip->ip_off &= 0xFF9F;

	hash_add(hash, pcap_socket, ntohl(ip->ip_src.s_addr), p, packet);
	hash_add(hash, pcap_socket, ntohl(ip->ip_dst.s_addr), p, packet);
}

/* I rewrote this when I found that my profiler said the libc version was too
 * slow */
static char *
itoa(int in)
{
	static char     buf[16];
	int             i = 15;

	buf[i--] = 0x00;

	while (in >= 10) {
		buf[i--] = ((in % 10) + '0');
		in /= 10;
	}
	buf[i--] = (in + '0');
	/*
	 * The beginning is calculated by the distance from i to the the
	 * character before the end (NULL) The end is 15, so the first
	 * available character is 14.  If the string representation of the
	 * number is one character long, 15 is 0x00, 14 is the digit, and 13
	 * is the current pointer.  Thus, the number should be buf + (i+1) or
	 * i+1
	 */
	return (buf + i + 1);
}

char *
ntoa(int a)
{
	static char     ret[40];

	ret[0] = 0x00;
	strcat(ret, itoa((a & 0xff000000) >> 24));
	strcat(ret, ".");
	strcat(ret, itoa((a & 0x00ff0000) >> 16));
	strcat(ret, ".");
	strcat(ret, itoa((a & 0x0000ff00) >> 8));
	strcat(ret, ".");
	strcat(ret, itoa(a & 0x000000ff));
	assert(strlen(ret) < sizeof(ret));

	return(ret);
}

/* shut down in a controlled way, close log file, close socket, and exit */
static void
signalShutdown(int s)
{
	shuttingDown=1;
	pcap_breakloop(pcap_socket);
}

static void
signalCleanup(int s)
{
	shouldCleanup=1;
	pcap_breakloop(pcap_socket);
}
