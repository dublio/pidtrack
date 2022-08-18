# pidtrack

Process cpu,mem,io resource-usage and resource-wait statistics

	Need CAP_NET_ADMIN

## Output Headers

### The top header
	The top header show the total statistics of all monitored processes.

	Time:		timestamp of this sample
	util:		total cpu.util
	user:		total cpu.util in user space.
	sys:		total cpu.util in kernel space.
	wr:		cpu wait rate, wr = wait_sum_time / (wait_sum_time + run_sum_time).
	cs/s:		context swich count per second for all monitored threads
	ics/s:		involuntary context swich count per second for all monitored threads
	read:		The disk IO read MB/s
	read:		The disk IO write MB/s
	rsysc/s:	read IO syscalls/s
	wsysc/s:	write IO syscalls/s

### The header with white backgroup
	The carmine fields indicate the output was sorted by this field

	pid:		process number
	tid:		thread number
	util(%):	cpu.util
	user(%):	cpu.util in user space
	sys(%):		cpu.util in kernel space
	wr:		cpu.wait_rate
	cs/s:		context switch per second
	ics/s:		involuntary context switch per second
	read:		disk IO read(MB/s)
	write:		disk IO write(MB/s)
	rsysc/s:	read IO syscalls/s
	wsysc/s:	write IO syscalls/s
	iowait:		the total time(us) when process cannot run caused by wait disk IO.
	memwait:	the total time(us) when process reclaim memory.
	cpuwait:	the total time(us) when process cannot run caused by cpu schedule.
	comm:		/proc/<pid>/task/<tid>/comm
	cmeline:	the first 32 charactors of /proc/<pid>/task/<tid>/cmdline

## Arguments
	pidtrack [-T] [-t <NUM>] [-s <key>] [-p pid1,pid2] [-g cgroup1,cgroup2] [-U util]

	-T			thread mode, show statistics for each thread
	-p			process list, separated by comma when monitor multiple processes.
	-g			cgroup list, separated by comma when monitor multiple cgroups.
					-p and -g can be used at same time.
	-i N		the sample interval in unit of millisecond
	-l		logging mode, append timestamp for each output line
	-s key		sort output by keys: util user sys wr cs ics read write io iowait memwai cpuwait
					the default sort field is cpuwait.
	-t N		only show top $NUM
	-U N		only output when all process's cpu.util > N
	-h			show this help
	-v			show version

## Usage example

	============================================================
	* monitor specific process
	pidtrack -p pid1,pid2

	pidtrack -p 1,2

	Time: 2021-02-04T11:02:48.324
	cpu:    0.00     cpu.usr: 0.00     cpu.sys: 0.00     wr: 0.00  read: 0.00     write: 0.00     pids: 2        tids: 2
	iowait: 0        memwait: 0        cpuwait: 0

	pid      tid      util(%)  user(%)  sys(%)   wr(%)    read     write    iowait   memwait  cpuwait  comm            cmdline
	1        1        0.00     0.00     0.00     0.00     0.00     0.00     0        0        0        systemd         /usr/lib/systemd/systemd --swit
	2        2        0.00     0.00     0.00     0.00     0.00     0.00     0        0        0        kthreadd

	============================================================
	* monitor a cgroup, sort output by IO read, only show top 5
	pidtrack -g /sys/fs/cgroup/<subsys>/ -s read -t 5

	Time: 2021-02-04T11:06:43.348
	cpu:    94.10    cpu.usr: 34.30    cpu.sys: 59.80    wr: 1.63  read: 252.26   write: 0.48     pids: 491      tids: 1692
	iowait: 2597938  memwait: 0        cpuwait: 15568

	pid      tid      util(%)  user(%)  sys(%)   wr(%)    read     write    iowait   memwait  cpuwait  comm            cmdline
	9059     9059     17.20    1.00     16.20    0.89     84.32    0.00     864299   0        1550     dd              dd if=/dev/sda of=/dev/null bs=
	9073     9073     15.60    0.70     14.90    0.74     84.24    0.00     866181   0        1165     dd              dd if=/dev/sda of=/dev/null bs=
	9014     9014     16.90    0.60     16.30    0.41     83.70    0.00     865318   0        702      dd              dd if=/dev/sda of=/dev/null bs=
	1        1        0.80     0.50     0.30     0.25     0.00     0.00     0        0        20       systemd         /usr/lib/systemd/systemd --swit
	2        2        0.00     0.00     0.00     0.00     0.00     0.00     0        0        0        kthreadd

	============================================================
	* monitor a cgroup, sort output by IO (read+write), only show top 5
	pidtrack -g /sys/fs/cgroup/<subsys>/ -s io -t 5

	Time: 2021-02-04T11:14:56.058
	cpu:    77.60    cpu.usr: 6.70     cpu.sys: 70.90    wr: 0.10  read: 134.05   write: 130.85   pids: 493      tids: 1712
	iowait: 3288401  memwait: 0        cpuwait: 783

	pid      tid      util(%)  user(%)  sys(%)   wr(%)    read     write    iowait   memwait  cpuwait  comm            cmdline
	19852    19852    13.20    0.90     12.30    0.02     71.03    0.00     890669   0        24       dd              dd if=/dev/sda of=/dev/null bs=
	19851    19851    19.30    0.70     18.60    0.04     0.00     65.91    771093   0        70       dd              dd if=/dev/zero of=./test.file
	18930    18930    30.70    0.40     30.30    0.06     0.00     64.89    712831   0        196      dd              dd if=/dev/zero of=./test.file
	18931    18931    8.50     0.30     8.20     0.02     63.02    0.00     913020   0        19       dd              dd if=/dev/sda of=/dev/null bs=
	640      640      0.00     0.00     0.00     0.00     0.00     0.05     305      0        0        jbd2/sda3-8

	============================================================
	* monitor a cgroup, sort output by CPU wait, only show top 5
	pidtrack -g /sys/fs/cgroup/<subsys>/ -s cpuwait -t 5

	Time: 2021-02-04T11:10:00.567
	cpu:    105.70   cpu.usr: 103.70   cpu.sys: 2.00     wr: 65.50 read: 0.00     write: 0.03     pids: 495      tids: 1714
	iowait: 0        memwait: 0        cpuwait: 2007202

	pid      tid      util(%)  user(%)  sys(%)   wr(%)    read     write    iowait   memwait  cpuwait  comm            cmdline
	34242    34242    33.70    33.40    0.30     66.93    0.00     0.00     0        0        681986   yes             yes
	34284    34284    33.20    33.00    0.20     66.63    0.00     0.00     0        0        662932   yes             yes
	34191    34191    33.30    33.10    0.20     66.53    0.00     0.00     0        0        661939   yes             yes
	4573     4573     0.60     0.50     0.10     2.31     0.00     0.00     0        0        142      bifrost2-agent  ./bin/bifrost2-agent -s start
	24462    24462    1.00     0.90     0.10     0.25     0.00     0.00     0        0        25       kubelet         /usr/bin/kubelet --logtostderr=
	10       10       0.00     0.00     0.00     100.00   0.00     0.00     0        0        19       rcu_sched

	============================================================
	* monitor a cgroup, sort output by context switch
	Terminal-1:
	echo $$ > /sys/fs/cgroup/cpu/cgroup.procs
	for ((i=0;i<3;i++)); do taskset -c 1 yes > /dev/null & done

	Terminal-2:
	pidtrack -g /sys/fs/cgroup/cpu/ -s cs -t 5

	Time: 2021-05-08T17:54:38.061
	cpu:    100.80   cpu.usr: 26.80    cpu.sys: 74.00    wr: 66.53 cs/s: 127.00   read: 0.00     write: 0.00     pids: 264      tids: 350
	iowait: 1835     memwait: 0        cpuwait: 2004088

	pid      tid      util(%)  user(%)  sys(%)   wr(%)    cs/s     read     write    iowait   memwait  cpuwait  comm            cmdline
	27285    27285    33.60    12.00    21.60    66.53    29.00    0.00     0.00     0        0        668000   yes             yes
	27283    27283    34.00    8.80     25.20    66.14    28.00    0.00     0.00     0        0        664004   yes             yes
	27284    27284    32.80    6.00     26.80    67.20    28.00    0.00     0.00     0        0        671997   yes             yes
	11       11       0.00     0.00     0.00     0.00     10.00    0.00     0.00     0        0        0        rcu_sched
	27282    27282    0.40     0.00     0.40     0.00     8.00     0.00     0.00     1835     0        0        kworker/u32:1-

## Changes
	v1.3.3 2021-05-08
		add field cs/s
	v1.3.4 2021-06-07
		add field ics/s
	v1.3.5 2021-09-16
		add support logging mode, append timestamp for each output line, for easy grep.
