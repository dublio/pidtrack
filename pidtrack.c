/*
 * pidtrack - the statistics of a process
 *
 * Copyright (C) 2020 Weiping Zhang <zwp10758@gmail.com>
 *
 * The license below covers all files distributed with cputil unless otherwise
 * noted in the file itself.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <linux/taskstats.h>
#include <linux/genetlink.h>
#include "list.h"

#define VERSION "v1.3.4"

LIST_HEAD(g_list);
LIST_HEAD(g_list_cgroup);

/*
 * Generic macros for dealing with netlink sockets. Might be duplicated
 * elsewhere. It is recommended that commercial grade applications use
 * libnl or libnetlink and use the interfaces provided by the library
 */
#define GENLMSG_DATA(glh)       ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh)    (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na)            ((void *)((char*)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)        (len - NLA_HDRLEN)


/* Maximum size of response requested or message sent */
#define MAX_MSG_SIZE    2048

struct msgtemplate {
	struct nlmsghdr n;
	union {
		struct genlmsghdr g;
		struct nlmsgerr e;
	};
	char buf[MAX_MSG_SIZE];
};

struct cgroup {
	struct list_head node;
	char path[PATH_MAX];
};

#define PID_STAT_NR 42
struct pid_stat {
/*01 */	int pid;
/*02 */	char comm[17];
/*03 */	char state;
/*04 */	int ppid;
/*05 */	int pgrp;
/*06 */	int session;
/*07 */	int tty_nr;
/*08 */	int tpgid;
/*09 */	unsigned int flags;
/*10 */	unsigned long minflt;
/*11 */	unsigned long cminflt;
/*12 */	unsigned long majflt;
/*13 */	unsigned long cmajflt;
/*14 */	unsigned long  utime;
/*15 */	unsigned long  stime;
/*16 */ long cutime;
/*17 */	long cstime;
/*18 */	long priority;
/*19 */	long nice;
/*20 */	long num_threads;
/*21 */	long itrealvalue;
/*22 */ unsigned long long starttine;
/*23 */ unsigned long vsize;
/*24 */ long rss;
/*25 */ unsigned long rsslim;
/*26 */ unsigned long startcode;
/*27 */ unsigned long endcode;
/*28 */ unsigned long startstack;
/*29 */ unsigned long kstkesp;
/*30 */ unsigned long kstkeip;
/*31 */ unsigned long signal;
/*32 */ unsigned long blocked;
/*33 */ unsigned long sinignore;
/*34 */ unsigned long sigcatch;
/*35 */ unsigned long wchan;
/*36 */ unsigned long nswap;
/*37 */ unsigned long cnswap;
/*38 */ int exit_signal;
/*39 */ int processor;
/*40 */ unsigned int rt_priority;
/*41 */ unsigned int policy;
/*42 */ unsigned long long delayacct_blkio_ticks;
/*TDB */
};

struct pid_track {
	struct list_head node;
	struct list_head child;
	struct pid_track *parent;
	int pid;
	int tid;
	int is_dummy; /* only account info for its children */
	int first_sample; /* first time to collect data for this @pt */
	struct taskstats pts[2];

	unsigned long long delta_io_delay_us, delta_mem_delay_us, delta_cpu_delay_us;
	unsigned long long delta_run;
	unsigned long delta_run_user, delta_run_sys;
	unsigned long long delta_context_switch, delta_involuntary_context_switch;
	unsigned long long delta_read_bytes, delta_write_bytes;
	float wait_rate;
	float csps; /* context switch per second: include voluntary and involuntary */
	float icsps; /* context switch per second: include voluntary and involuntary */
	float cpu_util, cpu_util_user, cpu_util_sys;
	float read_bps, write_bps;
	char cmdline[32]; /* only cut first 32 charactors */
	char comm[PR_SET_NAME];
};

enum {
	SORT_NONE,	/* -s nonde	: no sort */
	SORT_UTIL,	/* -s util	: sort by cpu.util */
	SORT_UTIL_USER,	/* -s user	: sort by cpu.util.user */
	SORT_UTIL_SYS,	/* -s sys	: sort by cpu.util.sys */
	SORT_WAITRATE,	/* -s waitrate	: sort by cpu.wait_rate */
	SORT_CS,	/* -s cs	: sort by cpu.context.switch */
	SORT_ICS,	/* -s ics	: sort by cpu.involuntary.context.switch */
	SORT_IO_READ,	/* -s read	: sort by io read */
	SORT_IO_WRITE,	/* -s write	: sort by io write */
	SORT_IO_WAIT,	/* -s iowait	: sort by io wait */
	SORT_MEM_WAIT,	/* -s memwait	: sort by mem wait */
	SORT_CPU_WAIT,	/* -s cpuwait	: sort by cpu wait */
	SORT_IO,	/* -s io	: sort by io (read + write) */
};

const char *const g_sort_str[] = {
	[SORT_NONE] = "none",
	[SORT_UTIL] = "util",
	[SORT_UTIL_USER] = "user",
	[SORT_UTIL_SYS] = "sys",
	[SORT_WAITRATE] = "wr",
	[SORT_CS] = "cs",
	[SORT_ICS] = "ics",
	[SORT_IO_READ] = "read",
	[SORT_IO_WRITE] = "write",
	[SORT_IO_WAIT] = "iowait",
	[SORT_MEM_WAIT] = "memwait",
	[SORT_CPU_WAIT] = "cpuwait",
	[SORT_IO] = "io",
};

int g_sort = SORT_CPU_WAIT;
int g_index;
int g_loop;
int g_thread;
char g_ts[64];
int g_interval_ms = 1000;
int g_socket_fd;
uint16_t g_family_id;
unsigned int g_nr_pid;
unsigned int g_nr_tid;
unsigned int g_top_nr = 0;

unsigned long long g_delta_run;
unsigned long g_delta_run_user;
unsigned long g_delta_run_sys;
unsigned long long g_delta_context_switch;
unsigned long long g_delta_involuntary_context_switch;
unsigned long long g_delta_read_bytes;
unsigned long long g_delta_write_bytes;
unsigned long long g_delta_io_delay_us;
unsigned long long g_delta_mem_delay_us;
unsigned long long g_delta_cpu_delay_us;

float g_cpu_util;
float g_cpu_util_sys;
float g_cpu_util_user;
float g_cpu_wr;
float g_read_bps;
float g_write_bps;
float g_csps;
float g_icsps;

int g_thresh_cpu_util;

char *g_arg_pid;
char *g_arg_cgroup;

static inline unsigned long long
timespec_delta_ns(struct timespec t1, struct timespec t2)
{
	unsigned long long delta_s, delta_ns;

	/*
	 * calculate time diff , t2 alwasy >= t1, that we can
	 * calculate it like fowllowing, no need care negative value.
	 */
	if (t2.tv_sec > t1.tv_sec) {
		delta_s = (t2.tv_sec - t1.tv_sec - 1);
		delta_ns = (1000000000 + t2.tv_nsec) -
			t1.tv_nsec;
		delta_ns += delta_s * 1000000000;
	} else {
		delta_ns = t2.tv_nsec - t1.tv_nsec;
	}

	return delta_ns;
}

static int nl_send_cmd(int sd, uint16_t nlmsg_type, uint32_t nlmsg_pid,
			uint8_t genl_cmd, uint16_t nla_type,
			void *nla_data, int nla_payload_len)
{
	struct nlattr *na;
	struct sockaddr_nl nladdr;
	int r, buflen, retry = 0;
	char *buf;
	struct msgtemplate msg;

	memset(&msg, 0, sizeof(msg));
	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = NLM_F_REQUEST;
	msg.n.nlmsg_seq = 0;
	msg.n.nlmsg_pid = nlmsg_pid;
	msg.g.cmd = genl_cmd;
	msg.g.version = 0x1;
	na = (struct nlattr *) GENLMSG_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_payload_len + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_payload_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	buf = (char *) &msg;
	buflen = msg.n.nlmsg_len ;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	while ((r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr,
			   sizeof(nladdr))) < buflen) {
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else {
			if (errno == EAGAIN) {
				/* retry 5 times before return failure */
				if (retry > 5)
					return -1;
				retry ++;
			} else
				return -1;
		}
	}

	return 0;
}

/**
 * read_pid_tid_file - read /proc/$pid/task/$tid/FILE
 */
static int read_pid_tid_file(int pid, int tid, const char *const name,
				char *buf, int len)
{
	int fd, ret;
	char path[128];

	memset(buf, 0, len);
	snprintf(path, sizeof(path), "/proc/%d/task/%d/%s", pid, tid, name);
	fd = open(path, O_RDONLY, 0444);
	if (fd == -1) {
#ifdef DBG
		fprintf(stderr, "failed to open %s\n", path);
#endif
		return -1;
	}

	ret = read(fd, buf, len - 1);
	if (ret < 0) {
#ifdef DBG
		fprintf(stderr, "failed to read %s\n", path);
#endif
		ret = -1;
		goto close;
	}
	ret = 0;

close:
	close(fd);
	return ret;
}

static inline int pidtrack_is_monitored(int pid, int tid)
{
	struct pid_track *p, *t;

	list_for_each_entry(p, &g_list, node) {
		if (pid != p->pid)
			continue;
		list_for_each_entry(t, &p->child, node) {
			if (tid == t->tid)
				return 1;
		}
	}

	return 0;
}

static inline struct pid_track *pidtrack_lookup_pid(int pid)
{
	struct pid_track *p;

	list_for_each_entry(p, &g_list, node) {
		if (p->pid == pid)
			return p;
	}

	return NULL;
}

static void pid_track_deinit_one(struct pid_track *pt)
{
	if (pt->is_dummy)
		g_nr_pid--;
	else
		g_nr_tid--;

	list_del(&pt->node);
	free(pt);
}

static void pidtrack_convert_cmdline(char *cmdline, size_t len)
{
	size_t i = 0;

	cmdline[len - 1] = '\0';

	for (i = 0; i < len - 1; i++) {
		if (cmdline[i] == '\0') {
			if (cmdline[i + 1] != '\0')
				cmdline[i] = ' ';
			else
				return;
		}
	}
}

static struct pid_track *pid_track_init_one(int pid, int tid)
{
	struct pid_track *pt;

	pt = malloc(sizeof(*pt));
	if (!pt) {
		fprintf(stderr, "failed to alloc memory\n");
		return NULL;
	}
	memset(pt, 0, sizeof(*pt));

	INIT_LIST_HEAD(&pt->node);
	INIT_LIST_HEAD(&pt->child);

	pt->first_sample = 1;
	pt->pid = pid;
	pt->tid = tid;

	/* get comm */
	if (read_pid_tid_file(pid, tid, "cmdline", pt->cmdline,
					sizeof(pt->cmdline)))
		snprintf(pt->cmdline, sizeof(pt->cmdline), "NULL");
	else {
		pidtrack_convert_cmdline(pt->cmdline, sizeof(pt->cmdline));
		strtok(pt->cmdline, "\n");
	}

	if (read_pid_tid_file(pid, tid, "comm", pt->comm, sizeof(pt->comm)))
		snprintf(pt->comm, sizeof(pt->comm), "NULL");
	else
		strtok(pt->comm, "\n");

	return pt;
}

static void pid_track_deinit_tid(struct pid_track *pt)
{
	struct pid_track *p, *tmp;

	list_for_each_entry_safe(p, tmp, &pt->child, node) {
		pid_track_deinit_one(p);
	}
}

static int pid_track_init_tid(struct pid_track *pt)
{
	DIR *dirp;
	struct dirent *entry;
	char dir_path[PATH_MAX];
	int tid;
	struct pid_track *p;

	snprintf(dir_path, PATH_MAX, "/proc/%d/task/", pt->pid);

	dirp = opendir(dir_path);
	if (!dirp) {
#ifdef DBG
		fprintf(stderr, "failed to open %s\n", dir_path);
#endif
		return -1;
	}

	for (;;) {
		errno = 0;
		entry = readdir(dirp);
		if (!entry && errno) {
#ifdef DBG
			fprintf(stderr, "failed to readdir %s\n", dir_path);
#endif
			goto out;
		}

		/* end of directory stream is reached */
		if (NULL == entry)
			break;

		/* skip . and .. */
		if (!strcmp(".", entry->d_name) || !strcmp("..", entry->d_name))
			continue;

		if (entry->d_type != DT_DIR)
			continue;

		if (sscanf(entry->d_name, "%d", &tid) != 1)
			continue;
#if 0
		if (tid == pt->pid)
			continue;
#endif
		/* check duplicated pid,tid pair */
		if (pidtrack_is_monitored(pt->pid, tid))
			continue;

		p = pid_track_init_one(pt->pid, tid);
		if (!p)
			continue;
		list_add_tail(&p->node, &pt->child);
		p->parent = pt;
		p->is_dummy = 0;
		g_nr_tid++;
	}

	closedir(dirp);
	return 0;

out:
	pid_track_deinit_tid(pt);
	closedir(dirp);

	return -1;
}

static void pid_track_deinit_pid(struct pid_track *pt)
{
	pid_track_deinit_tid(pt);
	pid_track_deinit_one(pt);
}

static int pid_track_init_pid(int pid)
{
	struct pid_track *pt;

	/* create dummy pt node when first time monitor this pid */
	if (!pidtrack_is_monitored(pid, pid)) {
		pt = pid_track_init_one(pid, pid);
		if (!pt)
			return -1;

		list_add_tail(&pt->node, &g_list);
		pt->is_dummy = 1;
		g_nr_pid++;
	} else {
		pt = pidtrack_lookup_pid(pid);
		if (!pt) {
			fprintf(stderr, "bug: not found struct for pid %d\n", pid);
			_exit(EXIT_FAILURE);
		}
	}

	/* scan new created thread of this pid */
	if (pid_track_init_tid(pt)) {
#ifdef DBG
		fprintf(stderr, "failed to init tid for pid %d\n", pid);
#endif
		pid_track_deinit_pid(pt);
		return -1;
	}

	return 0;
}

static int pid_track_rescan_new_tid(void)
{
	struct pid_track *p, *tmp;

	list_for_each_entry_safe(p, tmp, &g_list, node) {
		pid_track_init_pid(p->pid);
	}

	return 0;
}

static int pid_track_init(char *pids)
{
	char *p, *sp;
	int pid;

	p = strtok_r(pids, ",", &sp);
	if (1 != sscanf(p, "%d", &pid)) {
		fprintf(stderr, "wrong pid, skip it %d\n", pid);
	}

	while (p) {
		if (1 != sscanf(p, "%d", &pid)) {
			fprintf(stderr, "wrong pid, skip it %d\n", pid);
			goto next;
		}

		if (pid_track_init_pid(pid)) {
			fprintf(stderr, "wrong pid, skip it %d\n", pid);
			goto next;
		}
next:
		p = strtok_r(NULL, ",", &sp);
	}

	return 0;
}

static void pid_track_deinit(void)
{
	struct pid_track *p, *tmp;

	list_for_each_entry_safe(p, tmp, &g_list, node)
		pid_track_deinit_pid(p);
}

static void pid_track_init_cgroup_pid(struct cgroup *c)
{
	char file[PATH_MAX];
	char line[64]; /* 64 it long enough for int number */
	FILE *fp;
	int ret, pid;

	ret = snprintf(file, sizeof(file), "%s/cgroup.procs", c->path);
	if (ret < 0 || ret >= (int)sizeof(file)) {
		fprintf(stderr, "path is tool long: %s\n", c->path);
		return;
	}

	/* get all pid for this cgroup */
	fp = fopen(file, "r");
	if (!fp) {
#ifdef DBG
		fprintf(stderr, "failed to open %s\n", file);
#endif
		return;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (1 != sscanf(line, "%d", &pid))
			continue;
		pid_track_init_pid(pid);
	}

	fclose(fp);
}

static void pid_track_rescan_new_pid(void)
{
	struct cgroup *c;

	list_for_each_entry(c, &g_list_cgroup, node)
		pid_track_init_cgroup_pid(c);
}

static int pid_track_init_cgroup_one(const char *path)
{
	char file[PATH_MAX];
	struct cgroup *c;
	struct stat st;

	/* test cgroup exist ? */
	snprintf(file, sizeof(file), "%s/cgroup.procs", path);
	if (stat(file, &st)) {
#ifdef DBG
		fprintf(stderr, "failed to stat %s\n", file);
#endif
		return -1;
	}

	/* add this cgroup to global list */
	c = malloc(sizeof(*c));
	if (!c) {
#ifdef DBG
		fprintf(stderr, "failed to alloc memory\n");
#endif
		return -1;
	}

	snprintf(c->path, sizeof(c->path), "%s", path);
	list_add_tail(&c->node, &g_list_cgroup);

	/* get all pid for this cgroup */
	pid_track_init_cgroup_pid(c);

	return 0;
}

static void pid_track_deinit_cgroup_one(struct cgroup *c)
{
	list_del(&c->node);
	free(c);
}

static int pid_track_init_cgroup(char *cgroups)
{
	char *p, *sp;

	p = strtok_r(cgroups, ",", &sp);
	while (p) {
		if (pid_track_init_cgroup_one(p))
			fprintf(stderr, "wrong cgroup, skip it %s\n", p);

		p = strtok_r(NULL, ",", &sp);
	}

	return 0;
}

static void pid_track_deinit_cgroup(void)
{
	struct cgroup *c, *tmp;

	list_for_each_entry_safe(c, tmp, &g_list_cgroup, node)
		pid_track_deinit_cgroup_one(c);
}

static void pid_track_calc_data_tid(struct pid_track *pt)
{
	struct taskstats *pts_cur = &pt->pts[g_index];
	struct taskstats *pts_pre = &pt->pts[1 - g_index];

	/* first time to collect data */
	if (pt->first_sample) {
		pt->wait_rate = 0.0;
		pt->csps = 0.0;
		pt->icsps = 0.0;
		pt->cpu_util = 0.0;
		pt->delta_run = 0;
		pt->delta_run_user = 0;
		pt->delta_run_sys = 0;
		pt->delta_context_switch = 0;
		pt->delta_involuntary_context_switch = 0;
		pt->delta_read_bytes = 0;
		pt->delta_write_bytes = 0;
		pt->delta_io_delay_us = 0;
		pt->delta_mem_delay_us = 0;
		pt->delta_cpu_delay_us = 0;
		pt->first_sample = 0;
		return;
	}

	/* delay: io,mem,cpu and read,write bytes */
	pt->delta_io_delay_us = (pts_cur->blkio_delay_total - pts_pre->blkio_delay_total) / 1000ULL;
	pt->delta_cpu_delay_us = (pts_cur->cpu_delay_total - pts_pre->cpu_delay_total) / 1000ULL;
	pt->delta_mem_delay_us = (pts_cur->swapin_delay_total - pts_pre->swapin_delay_total) / 1000ULL;
	pt->delta_mem_delay_us += (pts_cur->freepages_delay_total - pts_pre->freepages_delay_total) / 1000ULL;


	pt->delta_run_user = pts_cur->ac_utime - pts_pre->ac_utime;
	pt->delta_run_sys = pts_cur->ac_stime - pts_pre->ac_stime;
	pt->delta_run = pt->delta_run_user + pt->delta_run_sys;
	pt->wait_rate = pt->delta_cpu_delay_us > 0 ?
			(float)pt->delta_cpu_delay_us / (float)(pt->delta_cpu_delay_us + pt->delta_run) : 0.0;

	/* context switch */
	pt->delta_context_switch = pts_cur->nvcsw - pts_pre->nvcsw;
	pt->delta_involuntary_context_switch = pts_cur->nivcsw - pts_pre->nivcsw;
	pt->csps = pt->delta_context_switch * 1000.0 / (float)g_interval_ms;
	pt->icsps = pt->delta_involuntary_context_switch * 1000.0 / (float)g_interval_ms;

	/* percent: 100 * delta_run / 1000 => delta_run /10 , the unit of delta_run is us */
	pt->cpu_util_user = (float)(pt->delta_run_user / 10) / (float)g_interval_ms;
	pt->cpu_util_sys = (float)(pt->delta_run_sys / 10) / (float)g_interval_ms;
	pt->cpu_util = pt->cpu_util_user + pt->cpu_util_sys;

	pt->delta_read_bytes = pts_cur->read_bytes - pts_pre->read_bytes;
	pt->delta_write_bytes = pts_cur->write_bytes - pts_pre->write_bytes;
	/* read/wirte bps */
	pt->read_bps = pt->delta_read_bytes * 1000.0 / (float)g_interval_ms;
	pt->write_bps = pt->delta_write_bytes * 1000.0 / (float)g_interval_ms;
}

static void pid_track_calc_data_pid(struct pid_track *pt)
{
	struct pid_track *p;

	/* reset counter */
	pt->delta_run = 0.0;
	pt->delta_run_user = pt->delta_run_sys = 0.0;
	pt->delta_context_switch = 0;
	pt->delta_read_bytes = pt->delta_write_bytes = 0;
	pt->delta_io_delay_us = 0;
	pt->delta_cpu_delay_us = 0;
	pt->delta_mem_delay_us = 0;

	list_for_each_entry(p, &pt->child, node) {
		pid_track_calc_data_tid(p);
		pt->delta_run += p->delta_run;
		pt->delta_run_user += p->delta_run_user;
		pt->delta_run_sys += p->delta_run_sys;
		pt->delta_context_switch += p->delta_context_switch;
		pt->delta_involuntary_context_switch += p->delta_involuntary_context_switch;
		pt->delta_read_bytes += p->delta_read_bytes;
		pt->delta_write_bytes += p->delta_write_bytes;
		pt->delta_io_delay_us += p->delta_io_delay_us;
		pt->delta_mem_delay_us += p->delta_mem_delay_us;
		pt->delta_cpu_delay_us += p->delta_cpu_delay_us;
	}
	
	pt->wait_rate = pt->delta_cpu_delay_us > 0 ?
			(float)pt->delta_cpu_delay_us / (float)(pt->delta_cpu_delay_us + pt->delta_run) : 0.0;

	/* percent: 100 * delta_run / 1000 => delta_run /10 , the unit of delta_run is us */
	pt->cpu_util_user = (float)(pt->delta_run_user / 10) / (float)g_interval_ms;
	pt->cpu_util_sys = (float)(pt->delta_run_sys / 10) / (float)g_interval_ms;
	pt->cpu_util = pt->cpu_util_user + pt->cpu_util_sys;

	/* context switch */
	pt->csps = pt->delta_context_switch * 1000.0 / (float)g_interval_ms;
	pt->icsps = pt->delta_involuntary_context_switch * 1000.0 / (float)g_interval_ms;

	/* read/wirte bps */
	pt->read_bps = pt->delta_read_bytes * 1000.0 / (float)g_interval_ms;
	pt->write_bps = pt->delta_write_bytes * 1000.0 / (float)g_interval_ms;
}

static void pid_track_cacl_data_global(void)
{
	/* percent: 100 * delta_run / 1000 => delta_run /10 , the unit of delta_run is us */
	g_cpu_util = (float)(g_delta_run / 10) / (float)g_interval_ms;
	g_cpu_util_user = (float)(g_delta_run_user / 10) / (float)g_interval_ms;
	g_cpu_util_sys = (float)(g_delta_run_sys/ 10) / (float)g_interval_ms;

	g_cpu_wr = g_delta_cpu_delay_us > 0 ? (float)(100 * g_delta_cpu_delay_us) / (float)(g_delta_run + g_delta_cpu_delay_us) : 0.0;
	g_csps = (float)(g_delta_context_switch * 1000.0) / (float)g_interval_ms;
	g_icsps = (float)(g_delta_involuntary_context_switch * 1000.0) / (float)g_interval_ms;
	g_read_bps = (float)(g_delta_read_bytes * 1000.0) / (float)g_interval_ms;
	g_write_bps = (float)(g_delta_write_bytes * 1000.0) / (float)g_interval_ms;
}

static void pid_track_calc_data(void)
{
	struct pid_track *p;

	/* reset global counter */
	g_delta_run = 0;
	g_delta_run_user = g_delta_run_sys = 0;
	g_delta_context_switch = 0;
	g_delta_read_bytes = g_delta_write_bytes = 0;
	g_delta_io_delay_us = 0;
	g_delta_mem_delay_us = 0;
	g_delta_cpu_delay_us = 0;

	list_for_each_entry(p, &g_list, node) {
		pid_track_calc_data_pid(p);
		g_delta_run += p->delta_run;
		g_delta_run_user += p->delta_run_user;
		g_delta_run_sys += p->delta_run_sys;
		g_delta_context_switch += p->delta_context_switch;
		g_delta_read_bytes += p->delta_read_bytes;
		g_delta_write_bytes += p->delta_write_bytes;
		g_delta_io_delay_us += p->delta_io_delay_us;
		g_delta_mem_delay_us += p->delta_mem_delay_us;
		g_delta_cpu_delay_us += p->delta_cpu_delay_us;
	}

	pid_track_cacl_data_global();

	g_index = 1 - g_index;
}

static void pid_track_show_extra_header(void)
{
	const char *fmt;

	if (g_cpu_wr < 50)
		fmt = "\033[32mcpu:    %-8.2f cpu.usr: %-8.2f cpu.sys: %-8.2f wr: %-5.2f cs/s: %-8.2f ics/s: %-8.2f read: %-8.2f write: %-8.2f pids: %-8d tids: %-8d \n"
			       "iowait: %-8llu memwait: %-8llu cpuwait: %-8llu\033[0m\n\n";
	else
		fmt = "\033[31mcpu:    %-8.2f cpu.usr: %-8.2f cpu.sys: %-8.2f wr: %-5.2f cs/s: %-8.2f ics/s: %-8.2f read: %-8.2f write: %-8.2f pids: %-8d tids: %-8d \n"
			       "iowait: %-8llu memwait: %-8llu cpuwait: %-8llu\033[0m\n\n";

	fprintf(stderr, fmt, g_cpu_util, g_cpu_util_user, g_cpu_util_sys, g_cpu_wr, g_csps, g_icsps, g_read_bps / 1048576.0,
		g_write_bps / 1048576.0, g_nr_pid, g_nr_tid,
		g_delta_io_delay_us, g_delta_mem_delay_us, g_delta_cpu_delay_us);
}

static void pid_track_show_header(void)
{
	struct tm *tm;
	struct timespec t;
	const char *fmt;

	clock_gettime(CLOCK_REALTIME, &t);
	tm = localtime(&t.tv_sec);
	snprintf(g_ts, sizeof(g_ts), "%4d-%02d-%02dT%02d:%02d:%02d.%03ld",
		 tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,tm->tm_min, tm->tm_sec, t.tv_nsec / 1000000L);

	fprintf(stderr, "\n\33[33mTime: %s\33[0m\n", g_ts);
	pid_track_show_extra_header();

	switch (g_sort) {
		case SORT_UTIL:
			fmt = "\33[47;30m%-8s %-8s \33[0m\33[47;35m%-8s\33[47;30m %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-15s %s\33[0m\n";
			break;
		case SORT_UTIL_USER:
			fmt = "\33[47;30m%-8s %-8s %-8s \33[0m\33[47;35m%-8s\33[47;30m %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-15s %s\33[0m\n";
			break;
		case SORT_UTIL_SYS:
			fmt = "\33[47;30m%-8s %-8s %-8s %-8s \33[0m\33[47;35m%-8s\33[47;30m %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-15s %s\33[0m\n";
			break;
		case SORT_WAITRATE:
			fmt = "\33[47;30m%-8s %-8s %-8s %-8s %-8s \33[0m\33[47;35m%-8s\33[47;30m %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-15s %s\33[0m\n";
			break;
		case SORT_CS:
			fmt = "\33[47;30m%-8s %-8s %-8s %-8s %-8s %-8s \33[0m\33[47;35m%-8s\33[47;30m %-8s %-8s %-8s %-8s %-8s %-8s %-15s %s\33[0m\n";
			break;
		case SORT_ICS:
			fmt = "\33[47;30m%-8s %-8s %-8s %-8s %-8s %-8s %-8s \33[0m\33[47;35m%-8s\33[47;30m %-8s %-8s %-8s %-8s %-8s %-15s %s\33[0m\n";
			break;
		case SORT_IO_READ:
			fmt = "\33[47;30m%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s \33[0m\33[47;35m%-8s\33[47;30m %-8s %-8s %-8s %-8s %-15s %s\33[0m\n";
			break;
		case SORT_IO_WRITE:
			fmt = "\33[47;30m%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s \33[0m\33[47;35m%-8s\33[47;30m %-8s %-8s %-8s %-15s %s\33[0m\n";
			break;
		case SORT_IO_WAIT:
			fmt = "\33[47;30m%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s \33[0m\33[47;35m%-8s\33[47;30m %-8s %-8s %-15s %s\33[0m\n";
			break;
		case SORT_MEM_WAIT:
			fmt = "\33[47;30m%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s \33[0m\33[47;35m%-8s\33[47;30m %-8s %-15s %s\33[0m\n";
			break;
		case SORT_CPU_WAIT:
			fmt = "\33[47;30m%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s \33[0m\33[47;35m%-8s\33[47;30m %-15s %s\33[0m\n";
			break;
		case SORT_IO:
			fmt = "\33[47;30m%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s \33[0m\33[47;35m%-8s %-8s\33[47;30m %-8s %-8s %-8s %-15s %s\33[0m\n";
			break;
		default: /* no sort */
			fmt = "\33[47;30m%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-15s %s\33[0m\n";
			break;
	}
	fprintf(stderr, fmt, "pid", "tid", "util(%)", "user(%)", "sys(%)", "wr(%)", "cs/s", "ics/s", "read", "write", "iowait", "memwait", "cpuwait", "comm", "cmdline");
}

static void pid_track_show_data_one(struct pid_track *pt)
{
	fprintf(stderr, "%-8d %-8d %-8.2f %-8.2f %-8.2f %-8.2f %-8.2f %-8.2f %-8.2f %-8.2f %-8llu %-8llu %-8llu %-15s %s\n",
		pt->pid, pt->tid,
		pt->cpu_util, pt->cpu_util_user, pt->cpu_util_sys,
		100.0 * pt->wait_rate, pt->csps, pt->icsps, pt->read_bps /1048576.0,
		pt->write_bps /1048576.0, pt->delta_io_delay_us, pt->delta_mem_delay_us,
		pt->delta_cpu_delay_us, pt->comm, pt->cmdline);
}

static int compare(const void *s1, const void *s2)
{
	struct pid_track *p1 = *(struct pid_track **)s1;
	struct pid_track *p2 = *(struct pid_track **)s2;
	float v1, v2;
	int ret = 0;

	switch (g_sort) {
		case SORT_UTIL:
			v1 = (float)p1->cpu_util;
			v2 = (float)p2->cpu_util;
			break;
		case SORT_UTIL_USER:
			v1 = (float)p1->cpu_util_user;
			v2 = (float)p2->cpu_util_user;
			break;
		case SORT_UTIL_SYS:
			v1 = (float)p1->cpu_util_sys;
			v2 = (float)p2->cpu_util_sys;
			break;
		case SORT_WAITRATE:
			v1 = (float)p1->wait_rate;
			v2 = (float)p2->wait_rate;
			break;
		case SORT_CS:
			v1 = (float)p1->csps;
			v2 = (float)p2->csps;
			break;
		case SORT_ICS:
			v1 = (float)p1->icsps;
			v2 = (float)p2->icsps;
			break;
		case SORT_IO_READ:
			v1 = (float)p1->read_bps;
			v2 = (float)p2->read_bps;
			break;
		case SORT_IO_WRITE:
			v1 = (float)p1->write_bps;
			v2 = (float)p2->write_bps;
			break;
		case SORT_IO_WAIT:
			v1 = (float)p1->delta_io_delay_us;
			v2 = (float)p2->delta_io_delay_us;
			break;
		case SORT_MEM_WAIT:
			v1 = (float)p1->delta_mem_delay_us;
			v2 = (float)p2->delta_mem_delay_us;
			break;
		case SORT_CPU_WAIT:
			v1 = (float)p1->delta_cpu_delay_us;
			v2 = (float)p2->delta_cpu_delay_us;
			break;
		case SORT_IO:
			v1 = (float)(p1->read_bps + p1->write_bps);
			v2 = (float)(p2->read_bps + p2->write_bps);
			break;
		default: /* no sort */
			return 0;
	}

	/* decrease order */
	if (v1 > v2)
		ret = -1;
	else if (v1 < v2)
		ret = 1;

	return ret;
}

static int pid_track_show_data(void)
{
	struct pid_track **pts, *p, *t;
	int ret = 0;
	unsigned int i, nr;

	if (g_thresh_cpu_util && (int)g_cpu_util < g_thresh_cpu_util)
		return 0;

	pid_track_show_header();

	if (g_thread) {
		nr = g_nr_tid;
	} else {
		nr = g_nr_pid;
	}

	pts = malloc(sizeof(struct pid_track *) * nr);
	if (!pts) {
		fprintf(stderr, "failed to alloc memory\n");
		return -1;
	}

	memset(pts, 0, sizeof(struct pid_track *) * nr);

	/* fillin pointer */
	i = 0;
	if (g_thread) {
		list_for_each_entry(p, &g_list, node) {
			list_for_each_entry(t, &p->child, node) {
				if (i == nr) {
					fprintf(stderr, "%s [%d]: Not sync, i=%d, nr=%d\n",
							__func__, __LINE__, i, nr);
					ret = -1;
					goto free;
				}
				pts[i++] = t;
			}
		}
	} else {
		list_for_each_entry(p, &g_list, node) {
				if (i == nr) {
					fprintf(stderr, "%s [%d]: Not sync, i=%d, nr=%d\n",
							__func__, __LINE__, i, nr);
					ret = -1;
					goto free;
				}
				pts[i++] = p;
		}
	}

	/* sort */
	if (g_sort != SORT_NONE)
		qsort(pts, nr, sizeof(struct pid_track *), compare);

	/* show data */
	for (i = 0; i < nr; i++) {
		/* only show top <NUM> pid/tid */
		if (g_top_nr && i >= g_top_nr)
			break;
		pid_track_show_data_one(pts[i]);
	}

free:
	free(pts);

	return ret;
}

static inline int pid_track_get_delay(struct pid_track *pt)
{
	int len, msg_len, len2, aggr_len;
	struct msgtemplate msg;
	struct nlattr *na;
	static int print_eperm = 0;

	len = nl_send_cmd(g_socket_fd, g_family_id, getpid(), TASKSTATS_CMD_GET,
				TASKSTATS_CMD_ATTR_PID, &pt->tid, sizeof(__u32));
	if (len < 0) {
#ifdef DBG
		fprintf(stderr, "send cgroupstats command failed %d/%d\n",
				pt->pid, pt->tid);
#endif
		return -1;
	}

	len = recv(g_socket_fd, &msg, sizeof(msg), 0);
	if (len < 0 || msg.n.nlmsg_type == NLMSG_ERROR ||
	   !NLMSG_OK((&msg.n), len)) {
		if (print_eperm == 0 && msg.e.error == -EPERM) {
			fprintf(stderr, "need CAP_NET_ADMIN: error:%d, %s\n",
				msg.e.error, strerror(-msg.e.error));
			fprintf(stderr, "you can run it with sudo, or #sudo setcap cap_net_admin `which pidtrack`\n");
			print_eperm = 1;
		}
		return -1;
	}

	na = (struct nlattr *) GENLMSG_DATA(&msg);
	if (na->nla_type != TASKSTATS_TYPE_AGGR_PID) {
#ifdef DBG
		fprintf(stderr, "wrong GENLMSG_DATA nla_type, %d/%d\n",
				pt->pid, pt->tid);
#endif
		return -1;
	}
	msg_len = GENLMSG_PAYLOAD(&msg.n);

	/* all receive data */
	len = 0;
	while (len < msg_len) {
		len += NLA_ALIGN(na->nla_len);

		if (na->nla_type != TASKSTATS_TYPE_AGGR_PID &&
			na->nla_type != TASKSTATS_TYPE_AGGR_TGID) {
#ifdef DBG
		fprintf(stderr, "wrong GENLMSG_DATA nla_type, %d/%d\n",
				pt->pid, pt->tid);
#endif
			goto next;
		}
		aggr_len = NLA_PAYLOAD(na->nla_len);
		na = (struct nlattr *) NLA_DATA(na);
		len2 = 0;
		while (len2 < aggr_len) {
			if (na->nla_type == TASKSTATS_TYPE_STATS) {
				memcpy(&pt->pts[g_index], (struct taskstats *) NLA_DATA(na),
					sizeof(struct taskstats));
			}
			len2 += NLA_ALIGN(na->nla_len);
			na = (struct nlattr *) ((char *) na + len2);
		}
next:
		na = (struct nlattr *) (GENLMSG_DATA(&msg) + len);
	}

	return 0;
}

static inline int pid_track_read_data_tid(struct pid_track *pt)
{
	/* read taskstats by netlink socket */
	if (pid_track_get_delay(pt)) {
#ifdef DBG
		fprintf(stderr, "failed to get delay pid/tid %d/%d\n",
			pt->pid, pt->tid);
#endif
		return -1;

	}

	return 0;
}

static inline int pid_track_read_data_pid(struct pid_track *pt)
{
	struct pid_track *p, *tmp;

	list_for_each_entry_safe(p, tmp, &pt->child, node) {
		if (pid_track_read_data_tid(p))
			pid_track_deinit_one(p);
	}

	/* no thread in this dummy pids */
	if (list_empty(&pt->child))
		return -1;

	return 0;
}

static int pid_track_read_data(void)
{
	struct pid_track *p, *tmp;

	list_for_each_entry_safe(p, tmp, &g_list, node) {
		if (pid_track_read_data_pid(p))
			pid_track_deinit_pid(p);
	}

	return 0;
}

static int pidtrack_setup_sort(const char *v)
{
	const char *p;
	unsigned int i;

	for (i = 0; i < sizeof(g_sort_str)/sizeof(g_sort_str[0]); i++) {
		p = g_sort_str[i];
		if (!strcmp(v, p)) {
			g_sort = i;
			return 0;
		}
	}

	fprintf(stderr, "wrong sort argument\n");

	return -1;
}

static int pidtrack_setup_top(const char *v)
{
	unsigned int tmp;

	if (1 != sscanf(v, "%u", &tmp)) {
		fprintf(stderr, "wrong top argument, it must be an valid number\n");
		return -1;
	}

	g_top_nr = tmp;

	return 0;
}
static void usage(void)
{
	fprintf(stderr, "pidtrack [-T] [-t <NUM>] [-s <key>] [-U N] [-i N] -p pid1,pid2\n");
	fprintf(stderr, "pidtrack [-T] [-t <NUM>] [-s <key>] [-U N] [-i N] -g cgroup1,cgroup2\n");
	fprintf(stderr, "pidtrack [-T] [-t <NUM>] [-s <key>] [-U N] [-i N] -p pid1,pid2 -g cgroup1,cgroup2\n");
	fprintf(stderr, "    -T: show statistics for each thread, normally only show process level data.\n");
	fprintf(stderr, "    -p: process list, seperated by comma\n");
	fprintf(stderr, "    -g: cgroup list, seperated by comma\n");
	fprintf(stderr, "    -s: the output can be sorted by key of: none util user sys wr cs ics read write io iowait memwait cpuwait\n");
	fprintf(stderr, "    -t: only show top <NUM> pid/tid\n");
	fprintf(stderr, "    -i: the sampling interval in unit of ms\n");
	fprintf(stderr, "    -U: only show data when cpu.util larger than it\n");
	fprintf(stderr, "    -v: show version\n");
	fprintf(stderr, "    -h: show this help\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Version:%s\n", VERSION);
	fprintf(stderr, "Bug report to: https://github.com/dublio/pidtrack/issues\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "    Get top-10 pid of a cgroup, sort by cpu wait\n");
	fprintf(stderr, "    pidtrack -g /sys/fs/cgroup/cpu/test/ -t 10 -s cpuwait\n\n");
	fprintf(stderr, "    Get top-10 Thread of a cgroup, sort by cpu wait\n");
	fprintf(stderr, "    pidtrack -g /sys/fs/cgroup/cpu/test/ -T -t 10 -s cpuwait\n\n");
	fprintf(stderr, "    Get top-10 pid of a cgroup, sort by IO read\n");
	fprintf(stderr, "    pidtrack -g /sys/fs/cgroup/cpu/test/ -t 10 -s read\n\n");
	fprintf(stderr, "    Get top-10 pid of a cgroup, sort by IO write\n");
	fprintf(stderr, "    pidtrack -g /sys/fs/cgroup/cpu/test/ -t 10 -s write\n\n");
	fprintf(stderr, "    Get top-10 pid of a cgroup, sort by IO read + write\n");
	fprintf(stderr, "    pidtrack -g /sys/fs/cgroup/cpu/test/ -t 10 -s io\n\n");
	fprintf(stderr, "    Get top-10 pid of a cgroup, sort by io wait\n");
	fprintf(stderr, "    pidtrack -g /sys/fs/cgroup/cpu/test/ -t 10 -s iowait\n\n");
	fprintf(stderr, "    Get top-10 pid of a cgroup, sort by memory wait\n");
	fprintf(stderr, "    pidtrack -g /sys/fs/cgroup/cpu/test/ -t 10 -s memwait\n\n");
	fprintf(stderr, "    For container:\n");
	fprintf(stderr, "    name=podname; ./pidtrack -g $(find /sys/fs/cgroup/cpu/ -name $(docker ps --no-trunc | grep -vE \"pause|CONTAINER\" | grep $name | awk '{print $1}' | head -1)) -t 20 -T\n");
}

static int pid_track_save_arg(char *arg, char **dst)
{
	size_t len = strlen(arg) + 1;
	char *buf;

	buf = malloc(len);
	if (!buf) {
		fprintf(stderr, "failed to alloc memory %lu\n", len);
		return -1;
	}
	memset(buf, 0, len);

	snprintf(buf, len, "%s", arg);
	*dst = buf;

	return 0;
}

static int pid_lat_nl_socket_init(void)
{
	struct sockaddr_nl addr;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0) {
		printf("failed to create socket\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("failed to bind socket\n");
		goto close;
	}

	g_socket_fd = fd;

	return 0;

close:
	close(fd);
	return -1;

}

static void pid_lat_nl_socket_deint(void)
{
	close(g_socket_fd);
}

static int pid_lat_get_family_id(void)
{
	struct msgtemplate msg;
	struct nlattr *na;
	int len, sd = g_socket_fd;
	char name[100];

	strcpy(name, TASKSTATS_GENL_NAME);
	len = nl_send_cmd(sd, GENL_ID_CTRL, getpid(), CTRL_CMD_GETFAMILY,
			CTRL_ATTR_FAMILY_NAME, (void *)name,
			strlen(TASKSTATS_GENL_NAME) + 1);
	if (len < 0) {
		printf("send getfamily command failed\n");
		return -1;
	}

	len = recv(sd, &msg, sizeof(msg), 0);
	if (len < 0 || msg.n.nlmsg_type == NLMSG_ERROR ||
	    !NLMSG_OK((&msg.n), len)) {
		printf("tailed to get msg\n");
		return -1;
	}

	/* FAMILY_NAME */
	na = (struct nlattr *) GENLMSG_DATA(&msg);
	/* FAMILY_ID */
	na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
	if (na->nla_type != CTRL_ATTR_FAMILY_ID) {
		printf("get wrong nla_type\n");
		return -1;
	}

	g_family_id = *(uint16_t *) NLA_DATA(na);

	return 0;
}

static int pid_lat_init(void)
{
	if (pid_lat_nl_socket_init())
		return -1;

	if (pid_lat_get_family_id())
		goto deinit_socket;

	return 0;

deinit_socket:
	pid_lat_nl_socket_deint();
	return -1;
}

static void pid_lat_deinit(void)
{
	pid_lat_nl_socket_deint();
}

static int parse_arg(int argc, char **argv)
{
	const char *opts = ":vhTp:s:t:g:i:U:";
	int k;

	while (1) {
		k = getopt(argc, argv, opts);
		switch (k) {
		case 'v':
			fprintf(stderr, "pidtrack - %s\n", VERSION);
			return 0;
		case 'T':
			g_thread = 1;
			break;
		case 'p':
			if (pid_track_save_arg(optarg, &g_arg_pid))
				return -1;
			break;
		case 'g':
			if (pid_track_save_arg(optarg, &g_arg_cgroup))
				return -1;
			break;
		case 'i' :
			if (1 != sscanf(optarg, "%d", &g_interval_ms))
				return -1;
			break;
		case 'U' :
			if (1 != sscanf(optarg, "%d", &g_thresh_cpu_util))
				return -1;
			break;
		case 's':
			if (pidtrack_setup_sort(optarg))
				goto usage;
			break;
		case 't':
			if (pidtrack_setup_top(optarg))
				goto usage;
			break;
		case 'h':
			goto usage;
		case ':':
			goto usage;
		default :
			goto out;
		}
	}

out:
	if (!g_arg_pid && !g_arg_cgroup) {
		fprintf(stderr, "please specify -p or -g\n\n");
		goto usage;
	}

	return 0;

usage:
	usage();
	return -1;
}

int main(int argc, char **argv)
{
	long sleep_us;
	struct timespec ts_start, ts_end;
	unsigned long long run_ns, interval_ns;
	struct timeval t_sleep;

	if (parse_arg(argc, argv))
		return -1;

	if (g_arg_pid && pid_track_init(g_arg_pid)) {
		fprintf(stderr, "failed to init pids\n");
		goto cleanup;
	}

	if (g_arg_cgroup && pid_track_init_cgroup(g_arg_cgroup)) {
		fprintf(stderr, "failed to init pids\n");
		goto cleanup;
	}

	if (pid_lat_init()) {
		fprintf(stderr, "failed to init pid latency\n");
		goto cleanup;
	}

	interval_ns = g_interval_ms * 1000000ULL;

	while (1) {
		clock_gettime(CLOCK_MONOTONIC, &ts_start);

		/* stop loop if there is no pid */
		if (g_nr_pid == 0)
			break;

		if (pid_track_read_data())
			goto cleanup;

		pid_track_calc_data();

		if (g_loop == 0)
			goto sleep;
		if (pid_track_show_data())
			goto cleanup;

		/* scan new created dynaimically process of these cgroups */
		pid_track_rescan_new_pid();

		/* scan new created dynaimically thread of these pids */
		pid_track_rescan_new_tid();
sleep:
		clock_gettime(CLOCK_MONOTONIC, &ts_end);
		run_ns = timespec_delta_ns(ts_start, ts_end);
		sleep_us = (long)(interval_ns - run_ns) / 1000;
		t_sleep.tv_sec = sleep_us / 1000000L;
		t_sleep.tv_usec = sleep_us % 1000000L;
		select(0, NULL, NULL, NULL, &t_sleep);
		g_loop++;
	}

cleanup:
	pid_track_deinit();
	pid_track_deinit_cgroup();
	if (g_arg_cgroup) {
		free(g_arg_cgroup);
		g_arg_cgroup = NULL;
	}
	if (g_arg_pid) {
		free(g_arg_pid);
		g_arg_pid = NULL;
	}

	pid_lat_deinit();

	return 0;
}
