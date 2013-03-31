/*
    Copyright (C) 2011,2012  rofl0r

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

#include "sha2/sha2.h"
#include "../lib/include/hashlist.h"

#ifndef NUM_DL_THREADS
#define NUM_DL_THREADS 16
#endif
#ifndef NUM_BUILD_THREADS
#define NUM_BUILD_THREADS 1
#endif
#ifndef SLEEP_MS
#define SLEEP_MS 500
#endif

typedef enum {
	PKGC_NONE = 0,
	PKGC_INSTALL,
	PKGC_REBUILD,
	PKGC_PREFETCH,
	PKGC_UPDATE,
} pkgcommands;

typedef struct {
	stringptr* name;
	uint64_t filesize;
	stringptr* tardir; //needed for tarballs that dont extract to a directory of the same name
	stringptr* sha512;
	stringptrlist* deps;
	stringptrlist* mirrors;
	stringptrlist* buildscript;
	int verified : 1;
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
	stringptrlist* build_errors;
	stringptrlist* skippkgs;
	procslots slots[JT_MAX];
	char builddir_buf[1024];
} pkgstate;

static const char* queue_names[] = { [JT_DOWNLOAD] = "download", [JT_BUILD] = "build", };

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
	die(SPL("syntax: butch command options\n\n"
	"commands: install, rebuild, prefetch, update\n\n"
	"pass an arbitrary number of package names as options\n\n"
	"\tinstall: installs one or more packages when they're not yet installed\n"
	"\t\t(list of installed packages is kept in pkg/installed.dat)\n"
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

static void getconfig(pkgstate* state) {
	pkgconfig* c = &state->cfg;
	stringptr_fromchar(getenv("A"), &c->arch);
	stringptr_fromchar(getenv("R"), &c->installroot);
	stringptr_fromchar(getenv("S"), &c->pkgroot);
	stringptr_fromchar(getenv("C"), &c->filecache);
	stringptr_fromchar(getenv("K"), &c->keep);
	stringptr_fromchar(getenv("LOGPATH"), &c->logdir);
	
	if(!c->arch.size) {
		die(SPL("need to set $A to your arch (i.e. x86_64, i386, arm, mips, ...)\n"));
	}
	if(!c->installroot.size) c->installroot = *(stringptr_copy(SPL("/")));
	if(!c->pkgroot.size) c->pkgroot = *(stringptr_copy(SPL("/src")));
	if(!c->filecache.size) c->filecache = *(stringptr_copy(SPL("/src/tarballs")));
	if(!c->keep.size) c->keep = *(stringptr_copy(SPL("/src/KEEP")));
	if(!c->logdir.size) c->logdir = *(stringptr_copy(SPL("/src/logs")));
	
#define check_access(X) if(access(c->X.ptr, W_OK) == -1) { \
		log_put(2, VARISL("cannot access "), VARISL(#X), VNIL); \
		log_perror(c->X.ptr); \
		die(SPL("check your environment vars, if the directory exists and that you have write perm (may need root)")); \
	}
	
	check_access(logdir);
	check_access(installroot);
	check_access(pkgroot);
	check_access(filecache);
	check_access(keep);
	
	ulz_snprintf(state->builddir_buf, sizeof(state->builddir_buf), "%s/build", c->pkgroot.ptr);
	stringptr_fromchar(state->builddir_buf, &c->builddir);
	if(access(state->builddir_buf, W_OK) == -1 && (errno != ENOENT || mkdir(state->builddir_buf, 0770) == -1)) {
		check_access(builddir);
	}
	
#undef check_access
	getconfig_skip(state);
}

static int get_tarball_filename(pkgstate* state, pkgdata* package, char* buf, size_t bufsize, int with_path) {
	if(stringptrlist_getsize(package->mirrors) == 0) return 0;
	char* fn = getfilename(stringptrlist_get(package->mirrors, 0));
	static const char* fmt_strings[] = { [0] = "%s", [1] = "%s/%s", };
	char* first_arg[] = { [0] = fn, [1] = state->cfg.filecache.ptr, };
	char* second_arg[] = { [0] = "", [1] = fn, };
	ulz_snprintf(buf, bufsize, fmt_strings[with_path], first_arg[with_path], second_arg[with_path]);
	return 1;
}

static void strip_fileext(stringptr* s) {
	char* dot = stringptr_rchr(s, '.');
	*dot = 0;
	s->size = dot - s->ptr;
	if((dot = stringptr_rchr(s, '.')) && !strcmp(dot, ".tar")) {
		s->size = dot - s->ptr;
		*dot = 0;
	}
}

/* outbuf must be at least 128+1 bytes */
static int sha512_hash(const char* filename, char *outbuf) {
	int fd;
	SHA512_CTX ctx;
	ssize_t nread;
	char buf[4*1024];
	int success = 0;
		
	fd = open(filename, O_RDONLY);
	if(fd == -1) return 0;
	SHA512_Init(&ctx);
	while(1) {
		nread = read(fd, buf, sizeof(buf));
		if(nread < 0) goto err;
		else if(nread == 0) break;
		SHA512_Update(&ctx, (const uint8_t*) buf, nread);
	}
	success = 1;
	err:
	close(fd);
	SHA512_End(&ctx, outbuf);
	return success;
}

static void get_package_filename(pkgstate *state, stringptr* packagename, char* buf, size_t buflen) {
	ulz_snprintf(buf, buflen, "%s/pkg/%s", state->cfg.pkgroot.ptr, packagename->ptr);
}

static int get_package_hash(pkgstate *state, stringptr* packagename, char* outbuf) {
	char buf[256];
	get_package_filename(state, packagename, buf, sizeof(buf));
	return sha512_hash(buf, outbuf);
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
	
	
	sec = iniparser_get_section(ini, SPL("main"));
	
	iniparser_getvalue(ini, &sec, SPL("tardir"), &val);
	if(val.size)
		out->tardir = stringptr_copy(&val);
	else {
		// must run after mirrors!
		stringptr fe;
		if(get_tarball_filename(state, out, buf, sizeof(buf), 0)) {
			stringptr_fromchar(buf, &fe);
			strip_fileext(&fe);
		} else {
			fe.size = 0;
			fe.ptr = 0;
		}
		out->tardir = stringptr_copy(&fe);
	}
	
	iniparser_getvalue(ini, &sec, SPL("sha512"), &val);
	if(val.size)
		out->sha512 = stringptr_copy(&val);
	else
		out->sha512 = 0;
	
	iniparser_getvalue(ini, &sec, SPL("filesize"), &val);
	if(val.size)
		out->filesize = strtoint64(val.ptr, val.size);
	else
		out->filesize = 0;
	
	sec = iniparser_get_section(ini, SPL("deps"));
	out->deps = stringptrlist_new(sec.linecount);
	
	for(start = sec.startline; start < sec.startline + sec.linecount; start++) {
		tmp = stringptrlist_get(ini, start);
		if(tmp->size) stringptrlist_add_strdup(out->deps, tmp);
	}
	
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
	die(SPL("package not existing"));
}

static void write_installed_dat(pkgstate* state);

static void get_installed_packages(pkgstate* state) {
	fileparser f;
	char buf[256];
	stringptr line;
	int oldformat = 0;
	
	ulz_snprintf(buf, sizeof(buf), "%s/pkg/installed.dat", state->cfg.pkgroot.ptr);
	if(fileparser_open(&f, buf)) goto err;
	while(!fileparser_readline(&f) && !fileparser_getline(&f, &line) && line.size) {
		char* p = line.ptr;
		while(*p && *p != ' ') p++;
		*p = 0;
		size_t l = (size_t) p - (size_t) line.ptr;
		stringptr *temp = SPMAKE(line.ptr, l);
		stringptrlist_add_strdup(state->installed_packages.names, temp);
		if(l == line.size) {
			/* old installed.dat format containing only package names */
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
	log_perror("failed to open installed.dat!");
}

static int is_installed(pkgstate* state, stringptr* packagename) {
	return stringptrlist_contains(state->installed_packages.names, packagename);
}

static int has_tarball(pkgstate* state, pkgdata* package) {
	char buf[256];
	if(!get_tarball_filename(state, package, buf, sizeof(buf), 1)) goto err;
	return (access(buf, R_OK) != -1);
	err:
	return 0;
}

static void free_package_data(pkgdata* data) {
	stringptrlist_freeall(data->buildscript);
	stringptrlist_freeall(data->deps);
	stringptrlist_freeall(data->mirrors);
	stringptr_free(data->name);
	stringptr_free(data->tardir);
	stringptr_free(data->sha512);
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
		ulz_fprintf(2, "[WARNING] recursion level above 100!\n");
		goto end;
	}
	if(!packagename->size) goto end;
	sblist* queue = state->queue[jt];
	stringptrlist* checklist = state->checked[jt];
	
	// check if we already processed this entry.
	if(stringptrlist_contains(checklist, packagename)) {
		goto end;
	}
	stringptrlist_add_strdup(checklist, packagename);
	
	if(is_in_queue(packagename, queue)) goto end;
	
	if(!force && is_installed(state, packagename)) {
		ulz_fprintf(1, "package %s is already installed, skipping %s\n", packagename->ptr, queue_names[jt]);
		goto end;
	}
	
	uint32_t hash = stringptr_hash(packagename);
	pkgdata* pkg = packagelist_get(state->package_list, packagename, hash);
	unsigned i;
	
	if(!pkg) {
		pkg = packagelist_add(state->package_list, packagename, hash);
		get_package_contents(state, packagename, pkg);
	}
	
	for(i = 0; i < stringptrlist_getsize(pkg->deps); i++) {
		queue_package(state, stringptrlist_get(pkg->deps, i), jt, 0); // omg recursion
	}
	
	if(
		// if sizeof mirrors is 0, it is a meta package
		(jt == JT_DOWNLOAD && stringptrlist_getsize(pkg->mirrors) && !has_tarball(state, pkg))
		|| (jt == JT_BUILD)
	) {
		add_queue(packagename, queue);
	}
end:
	depth--;
	
}

//return 0 on success.
//checks if filesize and/or sha512 matches, if used.
static int verify_tarball(pkgstate* state, pkgdata* package) {
	char tarfile[256];
	uint64_t len = 0;
	get_tarball_filename(state, package, tarfile, sizeof(tarfile), 1);
	if(package->filesize) {
		len = getfilesize(tarfile);
		if(len < package->filesize) {
			log_put(2, VARISL("WARNING: "), VARIC(tarfile), VARISL(" filesize too small!"), VNIL);
			return 1;
		} else if (len > package->filesize) {
			log_put(2, VARISL("WARNING: "), VARIC(tarfile), VARISL(" filesize too big!"), VNIL);
			return 2;
		}
	}
// testing the sha checksum can take *ages* on slow emulated CPUS.
// you can turn it off once you know the tarballs are good.
#ifndef DISABLE_CHECKSUM
	stringptr hash;
	char hashbuf[256];
	char* error;
	if(package->sha512) {
		if(!sha512_hash(tarfile, hashbuf)) {
			error = strerror(errno);
			log_put(2, VARISL("WARNING: "), VARIC(tarfile), VARISL(" failed to open: "), VARIC(error), VNIL);
			return 3;
		}
		hash.ptr = hashbuf; hash.size = 128;
		assert(hash.ptr[128] == 0 && hash.ptr[127] != 0);
		if(!EQ(&hash, package->sha512)) {
			log_put(2, VARISL("WARNING: "), VARIS(package->name), VARISL(" sha512 mismatch, got "), 
				VARIS(&hash), VARISL(", expected "), VARIS(package->sha512), VNIL);
			return 4;
		}
	}
#endif
	return 0;
}

static stringptr* make_config(pkgconfig* cfg) {
	stringptr* result = stringptr_concat(
		SPL("export A="),
		&cfg->arch,
		SPL("\n"),
		SPL("export R="),
		&cfg->installroot,
		SPL("\n"),
		SPL("export S="),
		&cfg->pkgroot,
		SPL("\n"),
		SPL("export C="),
		&cfg->filecache,
		SPL("\n"),
		SPL("export K="),
		&cfg->keep,
		SPL("\n"),
		SPNIL);
	return result;
}

static const stringptr* default_scripts[] = { 
	[JT_DOWNLOAD] = SPL(
	"#!/bin/sh\n"
	"%BUTCH_CONFIG\n"
	"export butch_package_name=%BUTCH_PACKAGE_NAME\n"
	"butch_cache_dir=\"$C\"\n"
	"wget -O \"$butch_cache_dir/%BUTCH_TARBALL\" '%BUTCH_MIRROR_URL'\n"
	),
	[JT_BUILD] = SPL(
	"#!/bin/sh\n"
	"%BUTCH_CONFIG\n"
	"butch_package_name=%BUTCH_PACKAGE_NAME\n"
	"butch_install_dir=\"$R\"\n"
	"butch_cache_dir=\"$C\"\n\n"
	"[ -z \"$CC\" ]  && CC=cc\n"
	"if %BUTCH_HAVE_TARBALL ; then\n"
	"\tcd \"$S/build\"\n" 
	"\t[ -e \"%BUTCH_TARDIR\" ] && rm -rf \"%BUTCH_TARDIR\"\n"
	"\ttar xf \"$butch_cache_dir/%BUTCH_TARBALL\" || (echo tarball error; exit 1)\n"
	"\tcd \"$S/build/%BUTCH_TARDIR\"\n"
	"fi\n"
	"%BUTCH_BUILDSCRIPT\n"
	),
};

static int create_script(jobtype ptype, pkgstate* state, pkg_exec* item, pkgdata* data) {
	stringptr *temp, *temp2, *config, tb;
	static const char* prefixes[] = { [JT_DOWNLOAD] = "dl", [JT_BUILD] = "build", };
	const char *prefix = prefixes[ptype];
	
	static const char* template_env_vars[] = { [JT_DOWNLOAD] = "BUTCH_DOWNLOAD_TEMPLATE", [JT_BUILD] = "BUTCH_BUILD_TEMPLATE" };
	char *custom_template =  getenv(template_env_vars[ptype]);
	
	const stringptr* default_script = default_scripts[ptype];;
	
	char buf[256];
	int hastarball;

	item->scripts.filename = stringptr_format("%s/%s_%s.sh", state->cfg.builddir.ptr, prefix, item->name->ptr);
	item->scripts.stdoutfn = stringptr_format("%s/%s_%s.log", state->cfg.logdir.ptr, prefix, item->name->ptr); 

	config = make_config(&state->cfg);

	if(ptype == JT_BUILD && !stringptrlist_getsize(data->buildscript)) {
		/* execute empty script when pkg has no build section */
		temp = stringptr_copy(SPL("#!/bin/sh\ntrue\n"));
		goto write_it;
	}

	hastarball = get_tarball_filename(state, data, buf, sizeof(buf), 0);
	
	stringptr* buildscr = (ptype == JT_BUILD ? stringptrlist_tostring(data->buildscript) : SPL(""));
	
	if(     // prevent erroneus scripts from trash our fs
		(ptype == JT_BUILD && hastarball && data->tardir->size && data->tardir->ptr[0] == '/') ||
		// bug
		(ptype == JT_DOWNLOAD && !hastarball)
	)
		abort();

	if(custom_template) {
		temp = stringptr_fromfile(custom_template);
		if(!temp) {
			log_puts(2, SPL("error reading custom_template, using default one\n"));
			goto def_script;
		}
	} else {
		def_script:
		temp = stringptr_copy((stringptr*) default_script);
	}

	temp2 = stringptr_replace(temp, SPL("%BUTCH_CONFIG"), config);
	stringptr_free(temp); temp = temp2;
	temp2 = stringptr_replace(temp, SPL("%BUTCH_PACKAGE_NAME"), item->name);
	stringptr_free(temp); temp = temp2;
	temp2 = stringptr_replace(temp, SPL("%BUTCH_BUILDSCRIPT"), buildscr);
	stringptr_free(temp); temp = temp2;
	
	temp2 = stringptr_replace(temp, SPL("%BUTCH_HAVE_TARBALL"), hastarball ? SPL("true") : SPL("false"));
	stringptr_free(temp); temp = temp2;
	temp2 = stringptr_replace(temp, SPL("%BUTCH_TARDIR"), hastarball ? data->tardir : SPL("$dummy"));
	stringptr_free(temp); temp = temp2;
	temp2 = stringptr_replace(temp, SPL("%BUTCH_TARBALL"), hastarball ? stringptr_fromchar(buf, &tb) : SPL("$dummy"));
	stringptr_free(temp); temp = temp2;
	
	if(ptype == JT_DOWNLOAD) {
		temp2 = stringptr_replace(temp, SPL("%BUTCH_MIRROR_URL"), 
						stringptrlist_get(data->mirrors, rand() % stringptrlist_getsize(data->mirrors)));
		stringptr_free(temp); temp = temp2;
	} else 
		stringptr_free(buildscr);
	
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
	for(i = 0; i < stringptrlist_getsize(item->deps); i++)
		if(!is_installed(state, stringptrlist_get(item->deps, i))) return 0;

	sblist_iter(state->queue[JT_DOWNLOAD], dlitem) {
		if(EQ(dlitem->name, item->name)) {
			return (dlitem->pid == PID_FINISHED); //download finished?
		}
	}
	return (!stringptrlist_getsize(item->mirrors) || has_tarball(state, item));
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
			ptrdiff_t skipidx;
			if((skipidx = in_skip_list(state, item->name)) >= 0) {
				// FIXME check if we need to free the stringptr member too (likely)
				sblist_delete(state->skippkgs, skipidx);
				item->pid = PID_FINISHED;
				continue;
			}
			
			pkg = packagelist_get(state->package_list, item->name, stringptr_hash(item->name));
			if(ptype == JT_DOWNLOAD || has_all_deps(state, pkg)) {
				if(ptype == JT_BUILD && !pkg->verified && stringptrlist_getsize(pkg->mirrors)) {
					if (! (pkg->verified = !(verify_tarball(state, pkg)))) {
						log_put(2, VARISL("WARNING: "), VARIS(item->name), VARISL(" failed to verify! please delete its tarball and retry downloading it."), VNIL);
						continue;
					}
				}
				launch_thread(ptype, state, item, pkg);
				(*slots_avail)--;
			}
		}
	}
}

static void prepare_slots(pkgstate* state) {
	state->slots[JT_DOWNLOAD].max = NUM_DL_THREADS;
	state->slots[JT_BUILD].max = NUM_BUILD_THREADS;
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
	ulz_snprintf(buf, sizeof(buf), "%s/pkg/installed.dat", state->cfg.pkgroot.ptr);
	ulz_snprintf(bak, sizeof(bak), "%s/pkg/installed.bak", state->cfg.pkgroot.ptr);
	if(rename(buf, bak) == -1) die_errno("trying to rename installed.dat to installed.bak failed");
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
	unlink(bak);
	return;
	err:
	rename(bak, buf);
	die(SPL("error writing to installed.dat"));
}

static void mark_finished(pkgstate* state, stringptr* name) {
	char hash[256];
	if(!get_package_hash(state, name, hash)) log_puterror(2, "failed to get pkg hash");
	ssize_t idx = stringptrlist_find(state->installed_packages.names, name);
	if(idx == -1) {
		stringptrlist_add_strdup(state->installed_packages.names, name);
		stringptrlist_add_strdup(state->installed_packages.hashes, SPMAKE(hash, 128));
		write_installed_dat(state);
	} else { /* update hash */
		// since we remove hashes and names from the installed list, this should never be needed */
		assert(EQ(stringptrlist_get(state->installed_packages.hashes, idx), SPMAKE(hash, 128)));
		if(0) {
			stringptr* e = stringptrlist_get(state->installed_packages.hashes, idx);
			free(e->ptr);
			char* e2 = stringptr_strdup(SPMAKE(hash, 128));
			stringptrlist_set(state->installed_packages.hashes, idx, e2, 128);
		}
	}
}

static void prepare_update(pkgstate* state, stringptrlist* packages2install) {
	char hash[256];
	size_t i;
	for(i = 0; i < sblist_getsize(state->installed_packages.names);) {
		stringptr* name = stringptrlist_get(state->installed_packages.names, i);
		if(!get_package_hash(state, name, hash)) log_puterror(2, "failed to get pkg hash");
		stringptr* h = stringptrlist_get(state->installed_packages.hashes, i);
		stringptr* h2 = SPMAKE(hash, 128);
		if(!EQ(h, h2)) {
			stringptrlist_add(packages2install, name->ptr, name->size);
			free(h->ptr);
			sblist_delete(state->installed_packages.names, i);
			sblist_delete(state->installed_packages.hashes, i);
		} else i++;
	}
}

static void warn_errors(pkgstate* state) {
	size_t i;
	stringptr* candidate;
	for(i = 0; i < stringptrlist_getsize(state->build_errors); i++) {
		candidate = stringptrlist_get(state->build_errors, i);
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
			goto retry;
		}
		
		if(exitstatus == 0) {
			// process exited gracefully
			if(jt == JT_DOWNLOAD) {
				/* verify size and checksum of the finished download */
				pkgdata* pkg;
				pkg = packagelist_get(state->package_list, listitem->name, stringptr_hash(listitem->name));
				ret = verify_tarball(state, pkg);
				pkg->verified = !ret;
				if(ret == 1) { // download too small, retry...
					log_put(2, VARISL("retrying too short download of "), VARIS(listitem->name), VNIL);
					goto retry;
				} else {
					// do not retry on success, hash mismatch or too big file.
					goto finished;
				}
			} else {
				mark_finished(state, listitem->name);
				goto finished;
			}
		} else {
			if(jt == JT_DOWNLOAD) {
				log_put(2, VARISL("got error "), VARII(WEXITSTATUS(exitstatus)), VARISL(" from download script of "), VARIS(listitem->name) ,VARISL(", retrying"), VNIL);
retry:
				listitem->pid = PID_WAITING;
			} else {
				stringptrlist_add_strdup(state->build_errors, listitem->name);
finished:
				listitem->pid = PID_FINISHED;
				
			}
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
	
	srand(time(0));
	
	getconfig(&state);
	state.installed_packages.names = stringptrlist_new(64);
	state.installed_packages.hashes = stringptrlist_new(64);
	get_installed_packages(&state);
	
	state.package_list = hashlist_new(64, sizeof(pkgdata));
	state.queue[JT_DOWNLOAD] = sblist_new(sizeof(pkg_exec), 64);
	state.queue[JT_BUILD] = sblist_new(sizeof(pkg_exec), 64);
	state.build_errors = stringptrlist_new(4);
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
		const int force[] = { [PKGC_REBUILD] = 1,  [PKGC_INSTALL] = 0 };
		queue_package(&state, curr_pkg, JT_DOWNLOAD, force[mode]);
		if(mode != PKGC_PREFETCH) 
			queue_package(&state, curr_pkg, JT_BUILD, force[mode]);
	}
	stringptrlist_freeall(packages2install);
	
	print_info(&state);
	prepare_slots(&state);
	
	while(process_queue(&state)) msleep(SLEEP_MS);
	
	int failed = stringptrlist_getsize(state.build_errors) != 0;
	
	if(state.skippkgs) goto skipfailure_check;
	
	if(!failed && (!(queue_empty(state.queue[JT_DOWNLOAD])) || !(queue_empty(state.queue[JT_BUILD])))) {
		ulz_fprintf(2, "[WARNING] circular reference detected!\n");
		failed = 1;
	}
	
	skipfailure_check:
	
	// clean up ...
	stringptrlist_freeall(state.build_errors);
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
