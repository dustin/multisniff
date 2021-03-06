/*
 * Copyright (c) 2006  dustin sallings
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
/*
  #include <getopt.h>
*/
#include "mymalloc.h"
#include "multisniff.h"

void
usage(char *name)
{
	fprintf(stderr, "Usage:  %s -i <intf> "
#ifdef HAVE_PCAP_DUMP_FLUSH
            "[-f] "
#endif
            "[-p] [-d <outdir>] "
            "[-m seconds] [-c seconds] [-F <filterfile>] [<filter>]\n",
            name);
	fprintf(stderr, "    -i specifies the interface to sniff (required).\n");
	fprintf(stderr, "    -d specifies the output directory.\n");
#ifdef HAVE_PCAP_DUMP_FLUSH
    fprintf(stderr, "    -F get a filter from a file.\n");
#endif
	fprintf(stderr, "    -f flush pcap files on each cleanup run.\n");
	fprintf(stderr, "    -p turns on promiscious sniffing.\n");
	fprintf(stderr, "    -m maximum age before closing file [60s].\n");
	fprintf(stderr, "    -c status update/flush frequency [5s].\n");
	fprintf(stderr, "    <filter> pcap filter expression.\n");
	exit(1);
}

static char *
readFile(const char *filename)
{
	FILE *in=NULL;
	char *rv=NULL;
	int rvsize=128;
	char buf[1024];

	in=fopen(filename, "r");
	if(in == NULL) {
		perror("fopen");
		exit(1);
	}

	rv=calloc(1, rvsize);
	assert(rv);
	while(fgets(buf, sizeof(buf), in) != NULL) {
		if(strlen(rv) + strlen(buf) > rvsize) {
			rv=realloc(rv, rvsize+=(strlen(buf)+1));
			assert(rv);
		}
		strcat(rv, buf);
	}

	/* Strip off the trailing whitespace */
	while(strlen(rv) > 0 && isspace(rv[strlen(rv)-1])) {
		rv[strlen(rv)-1]=0x00;
	}
	return rv;
}

int
main(int argc, char **argv)
{
	int             flags = 0;
	int             c = 0;
	extern char    *optarg;
	char           *filter = NULL;
	char           *outdir = ".";
	char           *intf = NULL;
	struct cleanupConfig conf;

	conf.maxAge=DEFAULT_MAX_PKT_AGE;
	conf.refreshTime=DEFAULT_CLEANUP_INTERVAL;

	while ((c = getopt(argc, argv, "fpi:d:F:m:c:")) != -1) {
		switch (c) {
		case 'f':
			flags |= FLAG_BIT(FLAG_FLUSH);
			break;
		case 'p':
			flags |= FLAG_BIT(FLAG_PROMISC);
			break;
		case 'F':
			filter = readFile(optarg);
			break;
		case 'd':
			outdir = strdup(optarg);
			break;
		case 'i':
			intf = strdup(optarg);
			break;
		case 'm':
			conf.maxAge=atoi(optarg);
			break;
		case 'c':
			conf.refreshTime=atoi(optarg);
			break;
		default:
			usage(argv[0]);
			exit(-1);
			break;	/* not reached */
		}
	}

    if (optind >= argc) {
        if(filter == NULL) {
            filter = "";
        }
    } else {
        int i=0;
        int size=0;
        for(i=optind; i<argc; i++) {
            size+=strlen(argv[i]);
            size+=1;
        }
        size+=1;
        filter=calloc(1, size);
        assert(filter);
        for(i=optind; i<argc; i++) {
            strcat(filter, argv[i]);
            strcat(filter, " ");
            assert(strlen(filter) < size);
        }
        /* Trim the trailing space */
        assert(filter[strlen(filter)-1] == ' ');
        filter[strlen(filter)-1]=0x00;
    }

    if (intf == NULL) {
        fprintf(stderr, "Must supply an interface\n");
        usage(argv[0]);
    }
    process(flags, intf, conf, outdir, filter);
    return (0);
}
