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
static int infd;

struct io_data {
	int outfd;
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

static int setup_context(unsigned entries, struct io_uring *ring) {
	int ret;

	ret = io_uring_queue_init(entries, ring, 0);
	if (ret < 0) {
		fprintf(stderr, "[!] queue_init: %s\n", strerror(-ret));
		return -1;
	}

	return 0;
}

static int submit_read_random_request(struct io_uring *ring, off_t size) {
	struct io_uring_sqe *sqe;
	struct io_data *data;

	int blocks = (int)size / BS;
	if (size % BS) {
		blocks++;
	}

	data = (struct io_data *)malloc(sizeof(*data) + sizeof(struct iovec) * blocks);
	if (data == NULL) {
		perror("malloc");
		return 1;
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
	io_uring_submit(ring);

	return 0;

err:
	if (data != NULL) {
		free(data);
	}

	return 1;
}

static int get_read_completion(struct io_uring *ring, const char *path) {
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_data *data;
	int fd, ret;

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		perror("io_uring_wait_cqe");
		goto err;
	}
	if (cqe->res < 0) {
		fprintf(stderr, "[!] io_uring_wait_cqe: %s\n", strerror(-(cqe->res)));
		goto err;
	}
	data = io_uring_cqe_get_data(cqe);

	fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	data->outfd = fd;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		perror("io_uring_get_sqe");
		goto err;
	}

	io_uring_prep_writev(sqe, data->outfd, data->iovecs, data->len, 0);
	io_uring_sqe_set_data(sqe, data);
	io_uring_submit(ring);

	io_uring_cqe_seen(ring, cqe);

	return 0;

err:
	close(fd);

	return 1;
}

static int finalize_completions(struct io_uring *ring) {
	struct io_uring_cqe *cqe;
	struct io_data *data;
	int ret;

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		perror("io_uring_wait_cqe");
		return 1;
	}
	if (cqe->res < 0) {
		fprintf(stderr, "[!] io_uring_wait_cqe: %s\n", strerror(-(cqe->res)));
		return 1;
	}

	data = io_uring_cqe_get_data(cqe);
	close(data->outfd);
	free(data);

	io_uring_cqe_seen(ring, cqe);

	return 0;
}

int main(int argc, char *argv[]) {
	struct io_uring ring;
	int i, opt;
	int size_bytes = 100,
		count = 10;
	char *outdir = "/tmp/";
	char **filenames;
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

	filenames = (char **)malloc(sizeof(char *) * count);
	if (filenames == NULL) {
		fprintf(stderr, "[!] Failed to allocate filenames's memory.\n");
		return EXIT_FAILURE;
	}
	for (i = 0; i < count; i++) {
		filenames[i] = (char *)malloc(sizeof(char) * (FILENAME_MAX+1));
		if (filenames[i] == NULL) {
			fprintf(stderr, "[!] Failed to allocate filename's memory.\n");
			return EXIT_FAILURE;
		}
		make_filename(filenames[i], FILENAME_MAX+1, i);
	}

	if (setup_context(QD, &ring)) {
		return EXIT_FAILURE;
	}

	clock_gettime(CLOCK_MONOTONIC, &before);
	for (i = 0; i < count; i++) {
		if (submit_read_random_request(&ring, size_bytes)) {
			fprintf(stderr, "[!] Failed to submit read /dev/urandom request.\n");
			return EXIT_FAILURE;
		}
		if (get_read_completion(&ring, filenames[i])) {
			fprintf(stderr, "[!] Failed to read & submit write.\n");
			return EXIT_FAILURE;
		}
		if (finalize_completions(&ring)) {
			fprintf(stderr, "[!] Failed to write.\n");
			return EXIT_FAILURE;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &after);

	printf("[+] Elapsed %f nsec.\n", (double)diff_nsec(before, after));

	for (i = 0; i < count; i++) {
		free(filenames[i]);
	}
	free(filenames);
	close(infd);
	io_uring_queue_exit(&ring);

	return EXIT_SUCCESS;
}
