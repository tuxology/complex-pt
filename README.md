Complex PT
----------

It is based on [simple-pt](https://github.com/andikleen/simple-pt) by Andi Kleen. The integration of PT in `perf` allows longer trace data to be recorded.
We therefore use complex-pt to record longer traces with perf and then extract the trace data and use similar approach of simple-pt to reconstruct the trace
The goal is to use our own decoder eventually (derived from `sptdecode`) and then perform custom analyses.

The project is named complex-pt because I have unintentionally made the whole charade of hardware trace recording more complex :-/

# Overview

simple-pt consists of a
* kernel driver which enables software tracepoints to assis in harware trace reconstruction
* sptcmd to gather traces, launch perf, extract PT traces from perf.data and show PT traces
* sptdecode to decode PT information
* fastdecode to dump raw PT traces

It uses the [libipt](https://github.com/01org/processor-trace) PT decoding library

Note that Linux 4.1 and later has an [integrated PT implementation](http://lwn.net/Articles/648154/) as part 
of Linux perf. gdb 7.10 also supports full debugging on top of PT. [Intel VTune](https://software.intel.com/en-us/intel-vtune-amplifier-xe)
also supports PT.

If you want a full production system please use one of these. simple-pt is an experimental implementation.

# Installation

Build and install libipt.

	git clone -b simple-pt https://github.com/01org/processor-trace
	cd processor-trace
	cmake .
	make
	sudo make install
	sudo ldconfig

Install libelf-elf-devel or elfutils-devel or similar depending on your distribution.

Optional install udis86 if you want to see disassembled instructions:

	git clone https://udis86.git.sourceforge.net/gitroot/udis86/udis86
	cd udis86
	./configure
	make

Clone simple-pt

	git clone https://github.com/tuxology/complex-pt
	cd complex-pt

Build the kernel module. May require installing kernel includes from your distribution.

	make

Install the kernel module

	sudo insmod simple-pt.ko

Build the user tools

	make user

If you installed udis86 use

	make user UDIS86=1

Check if your system supports PT

	./ptfeature

Build `ptparse` and place executable in complex-pt directory. Make sure the path of perf in sptcmd is set properly.

# Usage

Run a trace

	sudo ./sptcmd -c sleep 2
	sudo ./sptdecode -s pt.meta -p extracted.pt.0 | less

`sptcmd` loads and configures the kernel driver. It runs a program with trace. It always 
does a global trace. It runs `perf record` with the `intel_pt` event which gathers kernel trace in perf.data
`ptparse` then extracts PT data from the perf file and saves it (extracted.pt.N where N is the CPU number). 
It also writes side band information extracted from perf as well as trace generated from simple-pt module to the pt.meta file
which is needed to decode the trace later on.

sptdecode then decodes the trace for a CPU using the side band information.
When it should decode kernel code it needs to run as root to be able to
read /proc/kcore. If it's not run as root kernel code will not be shown.
