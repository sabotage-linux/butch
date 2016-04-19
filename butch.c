/*
    Copyright (C) 2011-2015  rofl0r

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <assert.h>

#include "../lib/include/stringptrlist.h"
#include "../lib/include/stringptr.h"
#include "../lib/include/strlib.h"
#include "../lib/include/logger.h"
#include "../lib/include/fileparser.h"
#include "../lib/include/iniparser.h"
#include "../lib/include/filelib.h"
#include "../lib/include/timelib.h"
#include "../lib/include/macros.h"
#include "../lib/include/hashlist.h"
#include "../lib/include/sha512.h"

#define VERSION "0.6.1"

#ifndef NUM_DL_THREADS
#define NUM_DL_THREADS 16
#endif
#ifndef NUM_BUILD_THREADS
#define NUM_BUILD_THREADS 1
#endif
#ifndef SLEEP_MS
#define SLEEP_MS 100
#endif

typedef enum {
	PKGC_NONE = 0,
	PKGC_INSTALL,
	PKGC_REBUILD,
	PKGC_PREFETCH,
	PKGC_UPDATE,
} pkgcommands;

typedef enum {
	DT_NONE = 0,
	DT_BUILD = 1 << 0, /* deps required for building a package for a target */
	DT_HOST= 1 << 1, /* deps required on the build host to build a package (for example perl if buildsys runs perl scripts) */
	DT_RUN = 1 << 2, /* deps required to use full functionality of a package (for example if a package needs external programs to execute its binaries) */
	DT_ALL = DT_BUILD | DT_HOST | DT_RUN,
} deptypes;

typedef struct {
	stringptr* name;
	stringptrlist* deps;
	stringptrlist* mirrors;
	stringptrlist* buildscript;
	stringptrlist* vars;
} pkgdata;

typedef struct {
	stringptr* filename;
	stringptr* stdoutfn;
} scriptinfo;

typedef struct {
	stringptr* name;
	pid_t pid;
	posix_spawn_file_actions_t fa;
	scriptinfo scripts;
} pkg_exec;

typedef struct {
	stringptr installroot;
	stringptr pkgroot;
	stringptr filecache;
	stringptr arch;
	stringptr logdir;
	stringptr builddir;
	stringptr keep;
	stringptr butch_db;
} pkgconfig;

typedef struct {
	unsigned avail;
	unsigned max;
} procslots;

typedef enum {
	JT_DOWNLOAD = 0,
	JT_BUILD,
	JT_MAX,
} jobtype;

struct installed_packages {
	stringptrlist* names;
	stringptrlist* hashes;
};

typedef struct {
	pkgconfig cfg;
	struct installed_packages installed_packages;
	hashlist* package_list;
	sblist* queue[JT_MAX];
	stringptrlist* checked[JT_MAX];
	stringptrlist* errors[JT_MAX];
	stringptrlist* skippkgs;
	procslots slots[JT_MAX];
	int depflags;
} pkgstate;

static const char* queue_names[] = {
	[JT_DOWNLOAD] = "download",
	[JT_BUILD] = "build",
};

static const char* template_env_vars[] = {
	[JT_DOWNLOAD] = "BUTCH_DOWNLOAD_TEMPLATE",
	[JT_BUILD] = "BUTCH_BUILD_TEMPLATE"
};

#define PID_WAITING ((pid_t) -1)
#define PID_FINISHED ((pid_t) 0)

__attribute__((noreturn))
static void die(stringptr* message) {
	log_puts(2, message);
	exit(1);
}

__attribute__((noreturn))
static void die_errno(const char* msg) {
	log_puterror(2, msg);
	exit(1);
}

static void syntax(void) {
	die(SPL(
	"BUTCH v" VERSION "\n"
	"syntax: butch command options\n\n"
	"commands: install, rebuild, prefetch, update\n\n"
	"pass an arbitrary number of package names as options\n\n"
	"\tinstall: installs one or more packages when they're not yet installed\n"
	"\t\t(list of installed packages is kept in /var/lib/butch.db unless\n"
	"\t\t overridden via BUTCHDB env var.)\n"
	"\trebuild: installs one or more packages even when they're already\n"
	"\t\tinstalled\n"
	"\tprefetch: only download the given package and all of its dependencies,\n"
	"\t\tunless they're not already in $C\n"
	"\tupdate: rebuild all packages that changed since last build\n"
	"\n"
	));
}

static ptrdiff_t in_skip_list(pkgstate *state, stringptr* pkg) {
	stringptr* tmp;
	if(!state->skippkgs) return -1;
	sblist_iter_counter(state->skippkgs, i, tmp) {
		if(EQ(tmp, pkg)) return i;
	}
	return -1;
}

/* entries in skiplist will be treated as if they failed to build
 * this allows to skip over failing packages and their dependencies
 * without the need to try to build them again. */
static void getconfig_skip(pkgstate* state) {
	stringptr tmp;
	state->skippkgs = 0;
	stringptr_fromchar(getenv("BUTCH_SKIPLIST"), &tmp);
	if(tmp.size) {
		state->skippkgs = stringptr_splitc(&tmp, ':');
		stringptrlist_dup_entries(state->skippkgs);
	}
}

static int getconfig_deps(pkgstate* state) {
	stringptr tmp;
	stringptr_fromchar(getenv("DEPS"), &tmp);
	if(!tmp.size) return DT_ALL;
	stringptrlist *l = stringptr_splitc(&tmp, ':');
	stringptr *item;
	int res = 0;
	sblist_iter(l, item) {
		if(EQ(item, SPL("all"))) return DT_ALL;
		if(EQ(item, SPL("host"))) res |= DT_HOST;
		else if(EQ(item, SPL("run"))) res |= DT_RUN;
		else if(EQ(item, SPL("build"))) res |= DT_BUILD;
	}
	return res;
}

static void getconfig(pkgstate* state) {
	pkgconfig* c = &state->cfg;
	stringptr_fromchar(getenv("A"), &c->arch);
	stringptr_fromchar(getenv("R"), &c->installroot);
	stringptr_fromchar(getenv("S"), &c->pkgroot);
	stringptr_fromchar(getenv("B"), &c->builddir);
	stringptr_fromchar(getenv("C"), &c->filecache);
	stringptr_fromchar(getenv("K"), &c->keep);
	stringptr_fromchar(getenv("LOGPATH"), &c->logdir);
	stringptr_fromchar(getenv("BUTCHDB"), &c->butch_db);

	if(!c->arch.size) {
		die(SPL("need to set $A to your arch (i.e. x86_64, i386, arm, mips, ...)\n"));
	}
	if(!c->installroot.size) c->installroot = *(stringptr_copy(SPL("/")));
	if(!c->pkgroot.size) c->pkgroot = *(stringptr_copy(SPL("/src")));
	if(!c->builddir.size) c->builddir = *(stringptr_concat(&c->pkgroot, SPL("/build"), SPNIL));
	if(!c->filecache.size) c->filecache = *(stringptr_copy(SPL("/src/tarballs")));
	if(!c->keep.size) c->keep = *(stringptr_copy(SPL("/src/KEEP")));
	if(!c->logdir.size) c->logdir = *(stringptr_copy(SPL("/src/logs")));
	if(!c->butch_db.size) c->butch_db = *(stringptr_copy(SPL("/var/lib/butch.db")));

#define check_access(X, MODE) if(access(c->X.ptr, MODE) == -1) { \
		log_put(2, VARISL("cannot access "), VARISL(#X), VNIL); \
		log_perror(c->X.ptr); \
		die(SPL("check your environment vars, if the directory exists and\nthat you have sufficient permissions (may need root)\n")); \
	} /* "" */

	check_access(logdir, W_OK);
	check_access(installroot, W_OK);
	check_access(pkgroot, R_OK);
	check_access(filecache, W_OK);
	check_access(keep, R_OK);

	if(access(c->builddir.ptr, W_OK) == -1 && (errno != ENOENT || mkdir(c->builddir.ptr, 0770) == -1)) {
		check_access(builddir, W_OK);
	}

	char buf[256], *p;
	ulz_snprintf(buf, sizeof buf, "%s", c->butch_db.ptr);
	if((p=strrchr(buf, '/'))) {
		*p = 0;
		if(access(buf, W_OK) == -1 && (errno != ENOENT || mkdir(buf, 0770) == -1)) {
			die(stringptr_concat(SPL("directory for "), &c->butch_db, SPL(" could not be created or no write perm.\n"), SPNIL));
		}
	}

#undef check_access
	int i;
	for (i=0;i<JT_MAX;i++)
		if(!getenv(template_env_vars[i]))
			die(stringptr_format("required env var %s not set!\n", template_env_vars[i]));

	getconfig_skip(state);
	state->depflags = getconfig_deps(state);
}

/* outbuf must be at least 128+1 bytes */
static void sha512_to_str(const unsigned char hash[64],char outbuf[129]) {
	size_t i;
	for (i = 0; i<64; ++i) {
		outbuf[2 * i] = "0123456789abcdef"[15 & (hash[i] >> 4)];
		outbuf[2 * i + 1] = "0123456789abcdef"[15 & hash[i]];
	}
	outbuf[2 * i] = 0;
}

static int sha512_hash(const char* filename, char outbuf[129]) {
	int fd;
	sha512_ctx ctx;
	ssize_t nread;
	char buf[4*1024];
	int success = 0;

	fd = open(filename, O_RDONLY);
	if(fd == -1) return 0;
	sha512_init(&ctx);
	while(1) {
		nread = read(fd, buf, sizeof(buf));
		if(nread < 0) goto err;
		else if(nread == 0) break;
		sha512_update(&ctx, (const uint8_t*) buf, nread);
	}
	success = 1;
	unsigned char* hash = sha512_end(&ctx);
	sha512_to_str(hash, outbuf);
	err:
	close(fd);
	return success;
}

static void get_package_filename(pkgstate *state, stringptr* packagename, char* buf, size_t buflen) {
	ulz_snprintf(buf, buflen, "%s/pkg/%s", state->cfg.pkgroot.ptr, packagename->ptr);
}

static int package_exists(pkgstate *state, stringptr* packagename) {
	char buf[256];
	get_package_filename(state, packagename, buf, sizeof(buf));
	return access(buf, R_OK) == 0;
}

static int get_package_hash(pkgstate *state, stringptr* packagename, char* outbuf) {
	char buf[256];
	get_package_filename(state, packagename, buf, sizeof(buf));
	return sha512_hash(buf, outbuf);
}

static void add_var(stringptrlist *list, stringptr *key, stringptr *value) {
	stringptr *temp = stringptr_concat(key, SPL("="), value, SPNIL);
	stringptrlist_add_strdup(list, temp);
	stringptr_free(temp);
}

// contract: out is already zeroed and contains only name
static void get_package_contents(pkgstate *state, stringptr* packagename, pkgdata* out) {
	char buf[256];
	get_package_filename(state, packagename, buf, sizeof(buf));

	ini_section sec;
	stringptr* fc = stringptr_fromfile(buf);
	stringptr val;

	if(!fc) goto err;
	stringptrlist* ini = stringptr_linesplit(fc);
	size_t start = 0;

	stringptr* tmp;

	sec = iniparser_get_section(ini, SPL("mirrors"));
	out->mirrors = stringptrlist_new(sec.linecount);

	for(start = sec.startline; start < sec.startline + sec.linecount; start++) {
		tmp = stringptrlist_get(ini, start);
		if(tmp->size) stringptrlist_add_strdup(out->mirrors, tmp);
	}

	sec = iniparser_get_section(ini, SPL("deps"));
	out->deps = stringptrlist_new(sec.linecount);

	static const struct { const stringptr secname; deptypes dt; } depmap[] = {
		{ .secname = SPINITIALIZER("deps"), .dt = DT_BUILD },
		{ .secname = SPINITIALIZER("deps.host"), .dt = DT_HOST },
		{ .secname = SPINITIALIZER("deps.run"), .dt = DT_RUN },
	};
	size_t i;
	for(i = 0; i < ARRAY_SIZE(depmap); i++) {
		if(state->depflags & depmap[i].dt) {
			sec = iniparser_get_section(ini, &depmap[i].secname);
			for(start = sec.startline; start < sec.startline + sec.linecount; start++) {
				tmp = stringptrlist_get(ini, start);
				if(tmp->size && in_skip_list(state, tmp) == -1) stringptrlist_add_strdup(out->deps, tmp);
			}
		}
	}

	sec = iniparser_get_section(ini, SPL("vars"));
	out->vars = stringptrlist_new(sec.linecount ? sec.linecount : 1);
	for(start = sec.startline; start < sec.startline + sec.linecount; start++) {
		tmp = stringptrlist_get(ini, start);
		stringptrlist_add_strdup(out->vars, tmp);
	}
	sec = iniparser_get_section(ini, SPL("main"));
	iniparser_getvalue(ini, &sec, SPL("tardir"), &val);
	if(val.size) add_var(out->vars, SPL("tardir"), &val);
	iniparser_getvalue(ini, &sec, SPL("sha512"), &val);
	if(val.size) add_var(out->vars, SPL("sha512"), &val);
	iniparser_getvalue(ini, &sec, SPL("filesize"), &val);
	if(val.size) add_var(out->vars, SPL("filesize"), &val);

	sec = iniparser_get_section(ini, SPL("build")); // the build section has always to come last
	if(sec.startline || sec.linecount) {
		start = sec.startline;
		sec = iniparser_file_as_section(ini); // iniparser may disinterpret lines starting with [
		// so be sure to use the entire rest of the file
		sec.startline = start;
		sec.linecount -= start;

		out->buildscript = stringptrlist_new(sec.linecount);

		for(start = sec.startline; start < sec.startline + sec.linecount; start++) {
			tmp = stringptrlist_get(ini, start);
			stringptrlist_add_strdup(out->buildscript, tmp);
		}
	} else
		out->buildscript = stringptrlist_new(1);

	stringptrlist_free(ini);
	stringptr_free(fc);
	return;
	err:
	log_perror(packagename->ptr);
	die(SPL("package not existing\n"));
}

static void write_installed_dat(pkgstate* state);

static void get_installed_packages(pkgstate* state) {
	fileparser f;
	char buf[256];
	stringptr line;
	int oldformat = 0;

	if(fileparser_open(&f, state->cfg.butch_db.ptr)) goto err;
	while(!fileparser_readline(&f) && !fileparser_getline(&f, &line) && line.size) {
		char* p = line.ptr;
		while(*p && *p != ' ') p++;
		*p = 0;
		size_t l = (size_t) p - (size_t) line.ptr;
		stringptr *temp = SPMAKE(line.ptr, l);
		stringptrlist_add_strdup(state->installed_packages.names, temp);
		if(l == line.size) {
			/* old butch.db format containing only package names */
			oldformat = 1;
			get_package_hash(state, temp, buf);
			temp = SPMAKE(buf, 128);
		} else {
			p++, l++;
			temp = SPMAKE(p, line.size - l);
		}
		stringptrlist_add_strdup(state->installed_packages.hashes, temp);
	}
	fileparser_close(&f);
	if(oldformat) write_installed_dat(state);
	return;
	err:
	if(errno != ENOENT) log_perror("failed to open butch.db!");
}

static int is_installed(pkgstate* state, stringptr* packagename) {
	return stringptrlist_contains(state->installed_packages.names, packagename);
}

static void free_package_data(pkgdata* data) {
	stringptrlist_freeall(data->buildscript);
	stringptrlist_freeall(data->deps);
	stringptrlist_freeall(data->mirrors);
	stringptrlist_freeall(data->vars);
	stringptr_free(data->name);
}

static int is_in_queue(stringptr* packagename, sblist* queue) {
	pkg_exec* item;
	sblist_iter(queue, item) {
		if(EQ(item->name, packagename))
			return 1;
	}
	return 0;
}

static void add_queue(stringptr* packagename, sblist* queue) {
	pkg_exec execdata;
	memset(&execdata, 0, sizeof(execdata));
	execdata.pid = PID_WAITING;
	execdata.name = stringptr_copy(packagename);
	sblist_add(queue, &execdata);
}

static pkgdata* packagelist_get(hashlist* list, stringptr* name, uint32_t hash) {
	sblist* bucket = hashlist_get(list, hash);
	pkgdata* result;
	if(bucket) {
		sblist_iter(bucket, result) {
			if(EQ(name, result->name))
				return result;
		}
	}
	return 0;
}

static pkgdata* packagelist_add(hashlist* list, stringptr* name, uint32_t hash) {
	pkgdata pkg_empty;
	memset(&pkg_empty, 0, sizeof(pkg_empty));
	pkg_empty.name = stringptr_copy(name);
	hashlist_add(list, hash, &pkg_empty);
	return packagelist_get(list, name, hash);
}

static void queue_package(pkgstate* state, stringptr* packagename, jobtype jt, int force) {
	static int depth = 0;
	depth++;
	if(depth > 100) {
		ulz_fprintf(2, "WARNING: recursion level above 100!\n");
		goto end;
	}
	if(!packagename->size) goto end;
	if(in_skip_list(state, packagename) >= 0) goto end;

	sblist* queue = state->queue[jt];
	stringptrlist* checklist = state->checked[jt];

	// check if we already processed this entry.
	if(stringptrlist_contains(checklist, packagename)) {
		goto end;
	}
	stringptrlist_add_strdup(checklist, packagename);

	if(is_in_queue(packagename, queue)) goto end;

	uint32_t hash = stringptr_hash(packagename);
	pkgdata* pkg = packagelist_get(state->package_list, packagename, hash);
	unsigned i;

	if(!pkg) {
		pkg = packagelist_add(state->package_list, packagename, hash);
		get_package_contents(state, packagename, pkg);
	}

	for(i = 0; i < stringptrlist_getsize(pkg->deps); i++) {
		queue_package(state, stringptrlist_get(pkg->deps, i), jt, 0); // omg recursion
		pkg = packagelist_get(state->package_list, packagename, hash);
	}

	if(!force && is_installed(state, packagename)) {
		ulz_fprintf(1, "package %s is already installed, skipping %s\n", packagename->ptr, queue_names[jt]);
		goto end;
	}

	if(
		// if sizeof mirrors is 0, it is a meta package
		(jt == JT_DOWNLOAD && stringptrlist_getsize(pkg->mirrors))
		|| (jt == JT_BUILD)
	) {
		add_queue(packagename, queue);
	}
end:
	depth--;

}

static stringptr* make_config(pkgconfig* cfg) {
#define EXPORT(K, V) SPL("export " K "="), V, SPL("\n")
	stringptr* result = stringptr_concat(
		EXPORT("A", &cfg->arch),
		EXPORT("R", &cfg->installroot),
		EXPORT("S", &cfg->pkgroot),
		EXPORT("C", &cfg->filecache),
		EXPORT("K", &cfg->keep),
		EXPORT("B", &cfg->builddir),
		SPNIL);
	return result;
#undef EXPORT
}

static stringptr *get_mirror_urls(pkgdata* data) {
	size_t i = 0;
	stringptr *new = stringptr_new(0);
	for(;i<stringptrlist_getsize(data->mirrors);i++)
		new = stringptr_concat(new, i ? SPL(" ") : SPL(""),
	                               stringptrlist_get(data->mirrors, i), SPNIL);
	return new;
}

static int create_script(jobtype ptype, pkgstate* state, pkg_exec* item, pkgdata* data) {
	stringptr *temp, *temp2, *config, *vars;
	static const char* prefixes[] = { [JT_DOWNLOAD] = "dl", [JT_BUILD] = "build", };
	const char *prefix = prefixes[ptype];

	char *custom_template =  getenv(template_env_vars[ptype]);

	item->scripts.filename = stringptr_format("%s/%s_%s.sh", state->cfg.builddir.ptr, prefix, item->name->ptr);
	item->scripts.stdoutfn = stringptr_format("%s/%s_%s.log", state->cfg.logdir.ptr, prefix, item->name->ptr);

	temp = make_config(&state->cfg);
	vars = stringptrlist_tostring(data->vars);
	config = stringptr_concat(temp, vars, SPNIL);
	stringptr_free(temp); stringptr_free(vars);

	if(ptype == JT_BUILD && !stringptrlist_getsize(data->buildscript)) {
		/* execute empty script when pkg has no build section */
		temp = stringptr_copy(SPL("#!/bin/sh\ntrue\n"));
		goto write_it;
	}

	stringptr* buildscr = (ptype == JT_BUILD ? stringptrlist_tostring(data->buildscript) : SPL(""));

	temp = stringptr_fromfile(custom_template);
	if(!temp) die(SPL("error reading custom_template, using default one\n"));

	temp2 = stringptr_replace(temp, SPL("%BUTCH_CONFIG"), config);
	stringptr_free(temp); temp = temp2;
	temp2 = stringptr_replace(temp, SPL("%BUTCH_PACKAGE_NAME"), item->name);
	stringptr_free(temp); temp = temp2;
	temp2 = stringptr_replace(temp, SPL("%BUTCH_BUILDSCRIPT"), buildscr);
	stringptr_free(temp); temp = temp2;
	temp2 = stringptr_replace(temp, SPL("%BUTCH_IS_REBUILD"), is_installed(state, item->name) ? SPL("true") : SPL("false"));
	stringptr_free(temp); temp = temp2;
	stringptr *temp3 = get_mirror_urls(data);

	temp2 = stringptr_replace(temp, SPL("%BUTCH_MIRROR_URLS"), temp3);
	stringptr_free(temp3);
	stringptr_free(temp); temp = temp2;

	if(ptype == JT_BUILD) stringptr_free(buildscr);

	write_it:
	stringptr_tofile(item->scripts.filename->ptr, temp);
	if(chmod(item->scripts.filename->ptr, 0775) == -1) die(SPL("error setting permission"));
	stringptr_free(config);
	stringptr_free(temp);
	return 1;
}

extern char** environ;

static void launch_thread(jobtype ptype, pkgstate* state, pkg_exec* item, pkgdata* data) {
	static const char* lt_msgs[] = { [JT_DOWNLOAD] = " downloading ", [JT_BUILD] = " building ", };
	char* arr[2];
	create_script(ptype, state, item, data);
	log_timestamp(1);
	log_put(1, VARICC(lt_msgs[ptype]), VARIS(item->name), VARISL(" ("), VARIS(item->scripts.filename), VARISL(") -> "), VARIS(item->scripts.stdoutfn), VNIL);

	arr[0] = item->scripts.filename->ptr;
	arr[1] = 0;

	posix_spawn_file_actions_init(&item->fa);
	posix_spawn_file_actions_addclose(&item->fa, 0);
	posix_spawn_file_actions_addclose(&item->fa, 1);
	posix_spawn_file_actions_addclose(&item->fa, 2);
	posix_spawn_file_actions_addopen(&item->fa, 0, "/dev/null", O_RDONLY, 0);
	posix_spawn_file_actions_addopen(&item->fa, 1, item->scripts.stdoutfn->ptr, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	posix_spawn_file_actions_adddup2(&item->fa, 1, 2);
	int ret = posix_spawnp(&item->pid, arr[0], &item->fa, 0, arr, environ);
	if(ret == -1) {
		log_perror("posix_spawn");
		die(SPL(""));
	}
}

// checks if all dependencies are installed
// then checks if the tarball is downloaded
// then checks if its either a metapackage or doesnt require a tarball.
static int has_all_deps(pkgstate* state, pkgdata* item) {
	size_t i;
	pkg_exec* dlitem;
	for(i = 0; i < stringptrlist_getsize(item->deps); i++) {
		stringptr *s = stringptrlist_get(item->deps, i);
		if(in_skip_list(state, s) == -1 && !is_installed(state, s)) return 0;
	}

	if(!stringptrlist_getsize(item->mirrors)) return 1;
	sblist_iter(state->queue[JT_DOWNLOAD], dlitem) {
		if(EQ(dlitem->name, item->name)) {
			if(dlitem->pid == PID_FINISHED) { //download finished?
				stringptr *s;
				sblist_iter(state->errors[JT_DOWNLOAD], s) {
					if(EQ(dlitem->name, s)) return 0;
				}
				return 1;
			} else return 0;
		}
	}
	return 0;
}

/* returns 1 if there are no unfinished (i.e. waiting or running)
 * processes in the queue, otherwise 0 */
static int queue_empty(sblist* queue) {
	pkg_exec* item;
	sblist_iter(queue, item) {
		if(item->pid != PID_FINISHED)
			return 0;
	}
	return 1;
}

static void fill_slots(jobtype ptype, pkgstate* state) {
	size_t i;
	pkg_exec* item;
	pkgdata* pkg;
	unsigned* slots_avail = &state->slots[ptype].avail;
	sblist* queue = state->queue[ptype];
	for(i = 0; *slots_avail && i < sblist_getsize(queue); i++) {
		item = sblist_get(queue, i);
		if(item->pid == PID_WAITING) {
			if(in_skip_list(state, item->name) >= 0) {
				item->pid = PID_FINISHED;
				continue;
			}

			pkg = packagelist_get(state->package_list, item->name, stringptr_hash(item->name));
			if(ptype == JT_DOWNLOAD || has_all_deps(state, pkg)) {
				launch_thread(ptype, state, item, pkg);
				(*slots_avail)--;
			}
		}
	}
}

static void prepare_slots(pkgstate* state) {
	char *p;
	p = getenv("BUTCH_DL_THREADS");
	state->slots[JT_DOWNLOAD].max = p ? atoi(p) : NUM_DL_THREADS;
	p = getenv("BUTCH_BUILD_THREADS");
	state->slots[JT_BUILD].max = p ? atoi(p) : NUM_BUILD_THREADS;
	state->slots[JT_DOWNLOAD].avail = state->slots[JT_DOWNLOAD].max;
	state->slots[JT_BUILD].avail = state->slots[JT_BUILD].max;
	fill_slots(JT_DOWNLOAD, state);
	fill_slots(JT_BUILD, state);
}

static void print_queue(pkgstate* state, jobtype jt) {
	sblist* queue = state->queue[jt];
	const char *queuename = queue_names[jt];
	pkg_exec* listitem;

	log_put(1, VARISL("*** "), VARICC(queuename), VARISL("queue ***"), VNIL);
	sblist_iter(queue, listitem) {
		log_puts(1, listitem->name);
		log_putln(1);
	}
}

static void print_info(pkgstate* state) {
	print_queue(state, JT_DOWNLOAD);
	print_queue(state, JT_BUILD);
}

static void write_installed_dat(pkgstate* state) {
	char buf[256];
	char bak[256];
	ulz_snprintf(buf, sizeof(buf), "%s", state->cfg.butch_db.ptr);
	ulz_snprintf(bak, sizeof(bak), "%s.bak", state->cfg.butch_db.ptr);
	/* block SIGINT */
	struct sigaction old, nu;
	int unblocksig = 0;
	if(!sigaction(SIGINT, 0, &old)) {
		unblocksig = 1;
		nu = old;
		nu.sa_handler = SIG_IGN;
		nu.sa_flags &= ~SA_SIGINFO;
		sigaction(SIGINT, &nu, 0);
	}

	int renamed = 1;
	if(rename(buf, bak) == -1) {
		renamed = 0;
		if(errno != ENOENT) log_puterror(2, "trying to rename butch.db failed");
	}

	int fd = open(buf, O_CREAT | O_TRUNC | O_RDWR, 0664);
	if(fd == -1) goto err;
	size_t i;
	assert(sblist_getsize(state->installed_packages.names) == sblist_getsize(state->installed_packages.hashes));
	for(i = 0; i < sblist_getsize(state->installed_packages.names); i++) {
		stringptr* s = stringptrlist_get(state->installed_packages.names, i);
		if(write(fd, s->ptr, s->size) != s->size) goto err;
		if(write(fd, " ", 1) != 1) goto err;
		s = stringptrlist_get(state->installed_packages.hashes, i);
		if(write(fd, s->ptr, s->size) != s->size) goto err;
		if(write(fd, "\n", 1) != 1) goto err;
	}
	close(fd);
	if(renamed) unlink(bak);
	if(unblocksig) sigaction(SIGINT, &old, 0);
	return;
	err:
	if(renamed) rename(bak, buf);
	die(SPL("error writing to butch.db"));
}

static void mark_finished(pkgstate* state, stringptr* name) {
	char hash[256];
	if(!get_package_hash(state, name, hash)) log_puterror(2, "failed to get pkg hash");
	ssize_t idx = stringptrlist_find(state->installed_packages.names, name);
	if(idx == -1) {
		stringptrlist_add_strdup(state->installed_packages.names, name);
		stringptrlist_add_strdup(state->installed_packages.hashes, SPMAKE(hash, 128));
	} else { /* update hash */
		stringptr* e = stringptrlist_get(state->installed_packages.hashes, idx);
		free(e->ptr);
		char* e2 = stringptr_strdup(SPMAKE(hash, 128));
		stringptrlist_set(state->installed_packages.hashes, idx, e2, 128);
	}
	write_installed_dat(state);
}

static void prepare_update(pkgstate* state, stringptrlist* packages2install) {
	char hash[256];
	size_t i;
	for(i = 0; i < sblist_getsize(state->installed_packages.names);) {
		stringptr* name = stringptrlist_get(state->installed_packages.names, i);
		if(!package_exists(state, name)) goto next;
		if(!get_package_hash(state, name, hash)) {
			log_puterror(2, "failed to get pkg hash");
			goto next;
		}
		stringptr* h = stringptrlist_get(state->installed_packages.hashes, i);
		stringptr* h2 = SPMAKE(hash, 128);
		if(!EQ(h, h2)) {
			stringptrlist_add(packages2install, name->ptr, name->size);
			free(h->ptr);
			sblist_delete(state->installed_packages.names, i);
			sblist_delete(state->installed_packages.hashes, i);
		} else {
			next:
			i++;
		}
	}
}

static void warn_errors(pkgstate* state) {
	size_t i;
	stringptr* candidate;
	for(i = 0; i < stringptrlist_getsize(state->errors[JT_BUILD]); i++) {
		candidate = stringptrlist_get(state->errors[JT_BUILD], i);
		log_put(2, VARISL("WARNING: "), VARIS(candidate), VARISL(" failed to build! wait for other jobs to finish."), VNIL);
	}
}

static void check_finished_processes(pkgstate* state, jobtype jt, int* had_event) {
	pkg_exec* listitem;
	sblist *queue = state->queue[jt];

	sblist_iter(queue, listitem) {
		int exitstatus, ret;
		// check for a running process.
		if(listitem->pid == PID_FINISHED || listitem->pid == PID_WAITING) continue;

		ret = waitpid(listitem->pid, &exitstatus, WNOHANG);

		// still busy
		if(ret == 0) continue;
		*had_event = 1;
		state->slots[jt].avail++;
		posix_spawn_file_actions_destroy(&listitem->fa);
		if(ret == -1) {
			log_perror("waitpid");
			listitem->pid = PID_WAITING;
			continue;
		}

		if(exitstatus == 0) {
			// process exited gracefully
			if(jt == JT_DOWNLOAD) {
				goto finished;
			} else {
				mark_finished(state, listitem->name);
				goto finished;
			}
		} else {
			if(jt == JT_DOWNLOAD)
				log_put(2, VARISL("got error "), VARII(WEXITSTATUS(exitstatus)), VARISL(" from download script of "), VARIS(listitem->name), VNIL);
			stringptrlist_add_strdup(state->errors[jt], listitem->name);
finished:
			listitem->pid = PID_FINISHED;
		}
	}
}

static void check_processes_and_fill_slots(pkgstate* state, jobtype jt, int* had_event) {
	check_finished_processes(state, jt, had_event);
	if(state->slots[jt].avail) fill_slots(jt, state);
}
static int process_queue(pkgstate* state) {
	int had_event = 0;

	check_processes_and_fill_slots(state, JT_DOWNLOAD, &had_event);
	check_processes_and_fill_slots(state, JT_BUILD, &had_event);

	if(had_event) warn_errors(state);

	int done = (state->slots[JT_DOWNLOAD].avail == state->slots[JT_DOWNLOAD].max &&
	         state->slots[JT_BUILD].avail == state->slots[JT_BUILD].max);

	return !done;
}

static void freequeue(sblist* queue) {
	pkg_exec* pe;
	sblist_iter(queue, pe) {
		stringptr_free(pe->name);
		stringptr_free(pe->scripts.filename);
		stringptr_free(pe->scripts.stdoutfn);
	}
	sblist_free(queue);
}

int main(int argc, char** argv) {
	pkgstate state;
	pkgcommands mode = PKGC_NONE;
	int i;

	const char* opt_strings[] = {
		[PKGC_INSTALL] = "install",
		[PKGC_REBUILD] = "rebuild",
		[PKGC_PREFETCH] = "prefetch",
		[PKGC_UPDATE] = "update",
	};

	if(argc < 2) syntax();

	for(i = PKGC_NONE + 1; (unsigned) i < ARRAY_SIZE(opt_strings); i++)
		if(!strcmp(argv[1], opt_strings[i]))
			mode = (pkgcommands) i;

	if(mode == PKGC_NONE || (mode != PKGC_UPDATE && argc < 3) || (mode == PKGC_UPDATE && argc > 2))
		syntax();

	/* if /dev/null is missing posix_spawn would silently fail when executing child processes */
	if(access("/dev/null", R_OK) == -1) {
		perror("error accessing /dev/null");
		die(SPL(""));
	}

	srand(time(0));

	getconfig(&state);
	state.installed_packages.names = stringptrlist_new(64);
	state.installed_packages.hashes = stringptrlist_new(64);
	get_installed_packages(&state);

	state.package_list = hashlist_new(64, sizeof(pkgdata));
	state.queue[JT_DOWNLOAD] = sblist_new(sizeof(pkg_exec), 64);
	state.queue[JT_BUILD] = sblist_new(sizeof(pkg_exec), 64);
	state.errors[JT_DOWNLOAD] = stringptrlist_new(4);
	state.errors[JT_BUILD] = stringptrlist_new(4);
	state.checked[JT_DOWNLOAD] = stringptrlist_new(64);
	state.checked[JT_BUILD] = stringptrlist_new(64);

	stringptrlist* packages2install = stringptrlist_new(16);

	if(mode == PKGC_UPDATE) {
		prepare_update(&state, packages2install);
		mode = PKGC_INSTALL;
	} else for(i = 2; i < argc; i++) {
		stringptr curr;
		// allow something like pkg/packagename to be passed
		char* pkg_name = strrchr(argv[i], '/');

		if(!pkg_name) pkg_name = argv[i];
		else pkg_name++;

		stringptr_fromchar(pkg_name, &curr);
		stringptrlist_add_strdup(packages2install, &curr);
	}

	stringptr *curr_pkg;
	sblist_iter(packages2install, curr_pkg) {
		const int force[] = {
			[PKGC_REBUILD] = 1,
			[PKGC_INSTALL] = 0,
			[PKGC_PREFETCH] = 1 };
		queue_package(&state, curr_pkg, JT_DOWNLOAD, force[mode]);
		if(mode != PKGC_PREFETCH)
			queue_package(&state, curr_pkg, JT_BUILD, force[mode]);
	}
	stringptrlist_freeall(packages2install);

	print_info(&state);
	prepare_slots(&state);

	while(process_queue(&state)) msleep(SLEEP_MS);

	int failed = stringptrlist_getsize(state.errors[JT_BUILD]) != 0;

	if(state.skippkgs) goto skipfailure_check;

	if(!failed && (!(queue_empty(state.queue[JT_DOWNLOAD])) || !(queue_empty(state.queue[JT_BUILD])))) {
		ulz_fprintf(2, "WARNING: circular reference or download error!\n");
		failed = 1;
	}

	skipfailure_check:

	// clean up ...
	stringptrlist_freeall(state.errors[JT_DOWNLOAD]);
	stringptrlist_freeall(state.errors[JT_BUILD]);
	stringptrlist_freeall(state.checked[JT_DOWNLOAD]);
	stringptrlist_freeall(state.checked[JT_BUILD]);
	stringptrlist_freeall(state.installed_packages.names);
	stringptrlist_freeall(state.installed_packages.hashes);
	if(state.skippkgs)
		stringptrlist_freeall(state.skippkgs);

	hashlist_iterator hit;
	hashlist_iterator_init(&hit);
	pkgdata* data;
	while((data = hashlist_next(state.package_list, &hit))) {
		free_package_data(data);
	}

	hashlist_free(state.package_list);

	freequeue(state.queue[JT_DOWNLOAD]);
	freequeue(state.queue[JT_BUILD]);

	log_timestamp(1);
	log_putspace(1);
	log_puts(1, SPL("done."));
	log_putln(1);

	return failed;
}
