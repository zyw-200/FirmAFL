#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>

static unsigned long progress_max;
static unsigned int progress_pcent;
static unsigned long progress_n_upd;
static unsigned int progress_prevsec;
static struct timespec progress_start;

#define PROGRESS_CHARS	50

void progress_init(unsigned long count)
{
	unsigned int i;

	progress_max = count;
	progress_pcent = 0;
	progress_n_upd = ULONG_MAX;
	progress_prevsec = UINT_MAX;

	printf("\r[");
	for (i = 0; i < PROGRESS_CHARS; i++)
		printf(" ");
	printf("] 0%%");
	fflush(stdout);
	clock_gettime(CLOCK_MONOTONIC, &progress_start);}

void progress_tick(unsigned long cur)
{
	unsigned int pcent, i, pos, sec;
	struct timespec now;

	pcent = (cur * 100) / progress_max;
	if (progress_pcent == pcent && cur < progress_n_upd &&
	    cur < progress_max)
		return;
	progress_pcent = pcent;
	pos = (pcent * PROGRESS_CHARS) / 101;
	clock_gettime(CLOCK_MONOTONIC, &now);

	printf("\r[");
	for (i = 0; i <= pos; i++)
		printf("=");
	for (; i < PROGRESS_CHARS; i++)
		printf(" ");
	printf("] %d%%", pcent);

	sec = now.tv_sec - progress_start.tv_sec;
	if (sec >= 5 && pcent > 0) {
		unsigned int persec = cur / sec;
		unsigned int rem_sec;

		if (!persec)
			persec = 1;
		progress_n_upd = cur + persec;
		rem_sec = ((sec * 100) + (pcent / 2)) / pcent - sec;
		if (rem_sec > progress_prevsec)
			rem_sec = progress_prevsec;
		progress_prevsec = rem_sec;
		if (rem_sec < 60)
			printf(" ETA:%ds     ", rem_sec);
		else {
			printf(" ETA:%d:%02d:%02d ",
				rem_sec / 3600,
				(rem_sec / 60) % 60,
				rem_sec % 60);
		}
	}

	fflush(stdout);
}

void progress_end(void)
{
	printf("\n");
}
