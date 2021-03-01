#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <liburing.h>

#define QD 128 // length of rings
#define BS 4096 // block size
#define NSECS_PER_SEC 1000000000UL // 1sec = 10^9nsec

#define RANDOM_FILE_PATH "/dev/urandom"

// fd of /dev/urandom (input file)
int infd;

struct io_data {
	int len;
	struct iovec iovecs[];
};


static inline long diff_nsec(struct timespec before, struct timespec after) {
	return ((after.tv_sec * NSECS_PER_SEC + after.tv_nsec) - (before.tv_sec * NSECS_PER_SEC + before.tv_nsec));
}

static char *make_filename(char *buf, size_t buf_size, int index) {
	size_t filename_len;

	memset(buf, 0, buf_size);
	snprintf(buf, buf_size, "tutorial%d", index);

	filename_len = strlen(buf);
	if (filename_len > FILENAME_MAX) {
		fprintf(stderr, "[!] filename is too long.\n");
		exit(EXIT_FAILURE);
	}

	return buf;
}

static int *register_outfiles(struct io_uring *ring, int nr_files) {
	int i, ret;
	int *fds;
	char filename[FILENAME_MAX+1];

	fds = (int *)malloc(sizeof(int) * nr_files);
	if (fds == NULL) {
		fprintf(stderr, "[!] Failed to allocate fds region.\n");
		return NULL;
	}

	for (i = 0; i < nr_files; i++) {
		make_filename(filename, FILENAME_MAX+1, i);

		fds[i] = open(filename, O_WRONLY|O_CREAT|O_EXCL, 0644);
		if (fds[i] < 0) {
			fprintf(stderr, "[!] Failed to open new outfile");
			free(fds);
			return NULL;
		}
	}

	ret = io_uring_register_files(ring, fds, nr_files);
	if (ret) {
		fprintf(stderr, "[!] Failed to register files: %s\n", strerror(-ret));
		free(fds);
		return NULL;
	}

	return fds;
}

static int setup_context(unsigned entries, struct io_uring *ring) {
	int ret;

	ret = io_uring_queue_init(entries, ring, 0);
	if (ret < 0) {
		fprintf(stderr, "[!] queue_init: %s\n", strerror(-ret));
		return -1;
	}

	return 0;
}

static int submit_read_random_requests(struct io_uring *ring, off_t size, int count) {
	struct io_uring_sqe *sqe;
	struct io_data *data;
	int i;

	int blocks = (int)size / BS;
	if (size % BS) {
		blocks++;
	}

	for (i = 0; i < count; i++) {
		data = (struct io_data *)malloc(sizeof(*data) + sizeof(struct iovec) * blocks);
		if (!data) {
			perror("malloc");
			goto err;
		}

		off_t bytes_remaining = size;
		int current_block = 0;
		while (bytes_remaining) {
			off_t bytes_to_read = bytes_remaining;
			if (bytes_to_read > BS) {
				bytes_to_read = BS;
			}

			data->iovecs[current_block].iov_len = bytes_to_read;

			void *tmpbuf;
			if (posix_memalign(&tmpbuf, BS, BS)) {
				perror("posix_memalign");
				goto err;
			}
			data->iovecs[current_block].iov_base = tmpbuf;

			current_block++;
			bytes_remaining -= bytes_to_read;
		}
		data->len = current_block;

		sqe = io_uring_get_sqe(ring);
		if (!sqe) {
			perror("io_uring_get_sqe");
			goto err;
		}

		io_uring_prep_readv(sqe, infd, data->iovecs, blocks, 0);
		io_uring_sqe_set_data(sqe, data);
	}

	io_uring_submit(ring);

	return 0;

err:
	if (data != NULL) {
		free(data);
	}

	return 1;
}

static int get_read_completions(struct io_uring *ring, int count) {
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_data *data;
	int i, ret;

	for (i = 0; i < count; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			perror("io_uring_wait_cqe");
			return 1;
		}
		if (cqe->res < 0) {
			fprintf(stderr, "[!] get_read_completions:io_uring_wait_cqe: %s\n", strerror(-(cqe->res)));
			return 1;
		}
		data = io_uring_cqe_get_data(cqe);

		sqe = io_uring_get_sqe(ring);
		if (!sqe) {
			perror("io_uring_get_sqe");
			return 1;
		}

		io_uring_prep_writev(sqe, i, data->iovecs, data->len, 0);
		sqe->flags |= IOSQE_FIXED_FILE;
		io_uring_sqe_set_data(sqe, data);

		io_uring_cqe_seen(ring, cqe);
	}

	io_uring_submit(ring);

	return 0;
}

static int finalize_completions(struct io_uring *ring, int count) {
	struct io_uring_cqe *cqe;
	struct io_data *data;
	int i, ret;

	for (i = 0; i < count; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			perror("io_uring_wait_cqe");
			return 1;
		}
		if (cqe->res < 0) {
			fprintf(stderr, "[!] finalize_completions:io_uring_wait_cqe: %s\n", strerror(-(cqe->res)));
			return 1;
		}

		data = io_uring_cqe_get_data(cqe);
		free(data);

		io_uring_cqe_seen(ring, cqe);
	}

	return 0;
}

int main(int argc, char *argv[]) {
	struct io_uring ring;
	int i, opt;
	int size_bytes = 100,
		count = 10;
	char *outdir = "/tmp/";
	struct timespec before, after;

	while ((opt = getopt(argc, argv, "o:s:c:")) != -1) {
		switch (opt) {
		case 'o':
			outdir = optarg;
			break;
		case 's':
			size_bytes = atoi(optarg);
			break;
		case 'c':
			count = atoi(optarg);
			break;
		default:
			fprintf(stderr, "Usage: %s -o [outdir] -s [size_bytes] -c [count]\n", argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (argc > optind + 1) {
		fprintf(stderr, "too many arguments\n");
		return EXIT_FAILURE;
	}

	if (chdir(outdir) == -1) {
		perror("chdir");
		return EXIT_FAILURE;
	}

	infd = open(RANDOM_FILE_PATH, O_RDONLY);
	if (infd < 0) {
		perror("open");
		return EXIT_FAILURE;
	}

	if (setup_context(QD, &ring)) {
		fprintf(stderr, "[!] Failed to setup urings\n");
		return EXIT_FAILURE;
	}

	int *fds = register_outfiles(&ring, count);
	if (fds == NULL) {
		fprintf(stderr, "[!] Failed to register outfiles\n");
		return EXIT_FAILURE;
	}

	clock_gettime(CLOCK_MONOTONIC, &before);
	if (submit_read_random_requests(&ring, size_bytes, count)) {
		fprintf(stderr, "[!] Failed to submit read /dev/urandom request.\n");
		return EXIT_FAILURE;
	}
	if (get_read_completions(&ring, count)) {
		fprintf(stderr, "[!] Failed to read & submit write.\n");
		return EXIT_FAILURE;
	}
	if (finalize_completions(&ring, count)) {
		fprintf(stderr, "[!] Failed to write.\n");
		return EXIT_FAILURE;
	}
	clock_gettime(CLOCK_MONOTONIC, &after);

	printf("[+] Elapsed %f nsec.\n", (double)diff_nsec(before, after));

	close(infd);
	for (i = 0; i < count; i++) {
		close(fds[i]);
	}
	io_uring_queue_exit(&ring);

	return EXIT_SUCCESS;
}
