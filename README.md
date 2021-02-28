# iouring-tutorial

This is my tutorial of io_uring.

The explanation of this repository is in my private slides.

## Requirements

OS: Ubuntu 20.04.1 LTS
Kernel: Linux 5.11+

* Other tools
    * liburing
    * bpftrace

## partX.c

1. Reads random bytes and writes it out as files.
2. Submits multiple SQEs at once.
3. Pre-register fds.
4. Enabling the SQPOLL feature.

## How to use


Executes make to build binaries.

```
$ make
gcc -Wall -o ./bin/part1 part1.c -luring
gcc -Wall -o ./bin/part2 part2.c -luring
gcc -Wall -o ./bin/part3 part3.c -luring
gcc -Wall -o ./bin/part4 part4.c -luring
```

Executes bpftrace program.

```
$ ./tools/uring_syscalls.bt
```

Executes binary.

```
$ ./bin/part1 -o /path/to/outdir -s 256 -c 10 # writes 10 files to /path/to/outdir (256 bytes per file)
```

