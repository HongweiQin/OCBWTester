#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define READ_SIZE (4096)

struct ocbwt_global_status {
	unsigned long nr_chnls;
};

struct ocbwt_pch_status {
	unsigned long inflight;
	unsigned long finished;
};


void *buf;
char *proc_file = "/proc/ocbwt";
struct ocbwt_global_status *gs;
struct ocbwt_pch_status *cs_array;

int main(int argc, char **argv)
{
	int fd;
	int num_read;
	unsigned int nr_chnl;
	int i, k;
	int testCount = 5;
	unsigned long saved[32];
	unsigned long first[32];
	unsigned long total;

	if (argc == 2) {
		testCount = atoi(argv[1]);
	}

	buf = malloc(READ_SIZE);
	if (!buf) {
		printf("Not enough memory\n");
		return 0;
	}

	fd = open(proc_file, O_RDONLY);
	if (!fd) {
		printf("err open\n");
		goto out;
	}

	for (k = 0; k < testCount; k++) {
		num_read = read(fd, buf, READ_SIZE);

		gs = buf;
		nr_chnl = gs->nr_chnls;

		cs_array = buf + sizeof(*gs);

		for (i = 0; i < nr_chnl; i++) {
			unsigned long finished, inflight;
			unsigned long pulse;

			finished = cs_array[i].finished;
			inflight = cs_array[i].inflight;
			pulse = finished - saved[i];
			printf("[%lu %lu]", pulse, inflight);
			saved[i] = finished;
			if (!k)
				first[i] = finished;
		}
		printf("\n");

		fflush(stdout);
		usleep(500000);
	}

	total = 0;
	for (i = 0; i < nr_chnl; i++) {
		printf("<%lu>", saved[i] - first[i]);
		total += saved[i] - first[i];
	}
	printf("\ntotal=%lu\n", total);
	close(fd);
out:
	free(buf);
	return 0;
}
