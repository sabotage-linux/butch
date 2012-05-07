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

#include "../lib/include/stringptrlist.h"
#include "../lib/include/stringptr.h"
#include "../lib/include/strlib.h"
#include "../lib/include/logger.h"
#include "../lib/include/fileparser.h"
#include "../lib/include/iniparser.h"
#include "../lib/include/filelib.h"
#include "../lib/include/macros.h"

#include "sha2/sha2.h"
#include "../lib/include/hashlist.h"

#define NUM_DL_THREADS 16
#define NUM_BUILD_THREADS 2

typedef enum {
	PKGC_NONE = 0,
	PKGC_INSTALL,
	PKGC_REBUILD,
	PKGC_PREFETCH,
	PKGC_REBUILD_ALL,
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
	JT_BUILD
} jobtype;

typedef struct {
	pkgconfig cfg;
	stringptrlist* installed_packages;
	hashlist* package_list;
	sblist* queue[JT_BUILD + 1];
	stringptrlist* checked[JT_BUILD + 1];
	stringptrlist* build_errors;
	procslots slots[JT_BUILD + 1];
	char builddir_buf[1024];
} pkgstate;

__attribute__((noreturn))
static void die(stringptr* message) {
	log_puts(2, message);
	exit(1);
}

static void syntax(void) {
	die(SPL("syntax: butch command options\n\n"
	"commands: install, rebuild, rebuildall, prefetch\n\n"
	"pass an arbitrary number of package names as options\n\n"
	"\tinstall: installs one or more packages when they're not yet installed\n"
	"\t\t(list of installed packages is kept in pkg/installed.dat)\n"
	"\trebuild: installs one or more packages even when they're already\n"
	"\t\tinstalled\n"
	"\trebuildall: installs one or more packages even when they're already\n"
	"\t\tinstalled, including all dependencies\n"
	"\tprefetch: only download the given package and all of its dependencies,\n"
	"\t\tunless they're not already in $C\n"
	"\n"
	));
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
		die(SPL("need to set $A to either x86_64 or i386!\n"));
	}
	if(!c->installroot.size) c->installroot = *(stringptr_copy(SPL("/")));
	if(!c->pkgroot.size) c->pkgroot = *(stringptr_copy(SPL("/src")));
	if(!c->filecache.size) c->filecache = *(stringptr_copy(SPL("/src/tarballs")));
	if(!c->keep.size) c->keep = *(stringptr_copy(SPL("/src/KEEP")));
	if(!c->logdir.size) c->logdir = *(stringptr_copy(SPL("/src/logs")));
	
#define check_access(X) if(access(c->X.ptr, W_OK) == -1) { \
		log_put(2, VARISL("cannot access "), VARISL(#X), NULL); \
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
}

static int get_tarball_filename(pkgdata* package, char* buf, size_t bufsize) {
	if(stringptrlist_getsize(package->mirrors) == 0) return 0;
	ulz_snprintf(buf, bufsize, "%s", getfilename(stringptrlist_get(package->mirrors, 0)));
	return 1;
}

static int get_tarball_filename_with_path(pkgconfig* cfg, pkgdata* package, char* buf, size_t bufsize) {
	if(stringptrlist_getsize(package->mirrors) == 0) return 0;
	ulz_snprintf(buf, bufsize, "%s/%s", cfg->filecache.ptr, getfilename(stringptrlist_get(package->mirrors, 0)));
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

// contract: out is already zeroed and contains only name
static void get_package_contents(pkgconfig* cfg, stringptr* packagename, pkgdata* out) {
	ini_section sec;
	char buf[256];
	ulz_snprintf(buf, sizeof(buf), "%s/pkg/%s", cfg->pkgroot.ptr, packagename->ptr);
	
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
		if(tmp->size) stringptrlist_add(out->mirrors, stringptr_strdup(tmp), tmp->size);
	}
	
	
	sec = iniparser_get_section(ini, SPL("main"));
	
	iniparser_getvalue(ini, &sec, SPL("tardir"), &val);
	if(val.size)
		out->tardir = stringptr_copy(&val);
	else {
		// must run after mirrors!
		stringptr fe;
		if(get_tarball_filename(out, buf, sizeof(buf))) {
			stringptr_fromchar(buf, &fe);
			strip_fileext(&fe);
		} else {
			fe.size = 0;
			fe.ptr = NULL;
		}
		out->tardir = stringptr_copy(&fe);
	}
	
	iniparser_getvalue(ini, &sec, SPL("sha512"), &val);
	if(val.size)
		out->sha512 = stringptr_copy(&val);
	else
		out->sha512 = NULL;
	
	iniparser_getvalue(ini, &sec, SPL("filesize"), &val);
	if(val.size)
		out->filesize = strtoint64(val.ptr, val.size);
	else
		out->filesize = 0;
	
	sec = iniparser_get_section(ini, SPL("deps"));
	out->deps = stringptrlist_new(sec.linecount);
	
	for(start = sec.startline; start < sec.startline + sec.linecount; start++) {
		tmp = stringptrlist_get(ini, start);
		if(tmp->size) stringptrlist_add(out->deps, stringptr_strdup(tmp), tmp->size);
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
			stringptrlist_add(out->buildscript, stringptr_strdup(tmp), tmp->size);
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

static void get_installed_packages(pkgconfig* cfg, stringptrlist* packages) {
	fileparser f;
	char buf[256];
	stringptr line;
	
	ulz_snprintf(buf, sizeof(buf), "%s/pkg/installed.dat", cfg->pkgroot.ptr);
	if(fileparser_open(&f, buf)) goto err;
	while(!fileparser_readline(&f) && !fileparser_getline(&f, &line) && line.size) {
		stringptrlist_add(packages, stringptr_strdup(&line), line.size);
	}
	fileparser_close(&f);
	return;
	err:
	log_perror("failed to open installed.dat!");
}

static int is_installed(stringptrlist* packages, stringptr* packagename) {
	return stringptrlist_contains(packages, packagename);
}

static int has_tarball(pkgconfig* cfg, pkgdata* package) {
	char buf[256];
	if(!get_tarball_filename_with_path(cfg, package, buf, sizeof(buf))) goto err;
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
	execdata.pid = (pid_t) -1;
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
	return NULL;
}

pkgdata* packagelist_add(hashlist* list, stringptr* name, uint32_t hash) {
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
	stringptrlist_add(checklist, stringptr_strdup(packagename), packagename->size);
	
	if(is_in_queue(packagename, queue)) goto end;
	
	if(!force && is_installed(state->installed_packages, packagename)) {
		ulz_fprintf(1, "package %s is already installed, skipping %s\n", packagename->ptr, jt == JT_DOWNLOAD ? "download" : "build");
		goto end;
	}
	
	uint32_t hash = stringptr_hash(packagename);
	pkgdata* pkg = packagelist_get(state->package_list, packagename, hash);
	unsigned i;
	
	if(!pkg) {
		pkg = packagelist_add(state->package_list, packagename, hash);
		get_package_contents(&state->cfg, packagename, pkg);
	}
	
	for(i = 0; i < stringptrlist_getsize(pkg->deps); i++) {
		queue_package(state, stringptrlist_get(pkg->deps, i), jt, force == -1 ? -1 : 0); // omg recursion
	}
	
	if(
		// if sizeof mirrors is 0, it is a meta package
		(jt == JT_DOWNLOAD && stringptrlist_getsize(pkg->mirrors) && !has_tarball(&state->cfg, pkg))
		|| (jt == JT_BUILD && stringptrlist_getsize(pkg->buildscript))
	) {
		add_queue(packagename, queue);
	}
	// in case a rebuild is forced of an installed package, but the tarball is missing, redownload
	if(force && jt == JT_BUILD && stringptrlist_getsize(pkg->mirrors) && !has_tarball(&state->cfg, pkg)) {
		queue_package(state, packagename, JT_DOWNLOAD, 1);
	}
	
end:
	depth--;
	
}

//return 0 on success.
//checks if filesize and/or sha512 matches, if used.
static int verify_tarball(pkgconfig* cfg, pkgdata* package) {
	char buf[4096];
	char* error;
	SHA512_CTX ctx;
	int fd;
	uint64_t pos, len = 0, nread;
	stringptr hash;
	get_tarball_filename_with_path(cfg, package, buf, sizeof(buf));
	if(package->filesize) {
		len = getfilesize(buf);
		if(len < package->filesize) {
			log_put(2, VARISL("WARNING: "), VARIC(buf), VARISL(" filesize too small!"), NULL);
			return 1;
		} else if (len > package->filesize) {
			log_put(2, VARISL("WARNING: "), VARIC(buf), VARISL(" filesize too big!"), NULL);
			return 2;
		}
	}
	if(package->sha512) {
		if(!len) len = getfilesize(buf);
			
		fd = open(buf, O_RDONLY);
		if(fd == -1) {
			error = strerror(errno);
			log_put(2, VARISL("WARNING: "), VARIC(buf), VARISL(" failed to open: "), VARIC(error), NULL);
			return 3;
		}
		SHA512_Init(&ctx);
		pos = 0;
		while(pos < len) {
			nread = read(fd, buf, sizeof(buf));
			SHA512_Update(&ctx, (const uint8_t*) buf, nread);
			pos += nread;
		}
		close(fd);
		SHA512_End(&ctx, (char*) buf);
		hash.ptr = buf; hash.size = strlen(buf);
		if(!EQ(&hash, package->sha512)) {
			log_put(2, VARISL("WARNING: "), VARIS(package->name), VARISL(" sha512 mismatch, got "), 
				VARIS(&hash), VARISL(", expected "), VARIS(package->sha512), NULL);
			return 4;
		}
	}
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
		NULL);
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
	hastarball = get_tarball_filename(data, buf, sizeof(buf));
	
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
	log_put(1, VARICC(lt_msgs[ptype]), VARIS(item->name), VARISL(" ("), VARIS(item->scripts.filename), VARISL(") -> "), VARIS(item->scripts.stdoutfn), NULL);

	arr[0] = item->scripts.filename->ptr;
	arr[1] = NULL;
	
	posix_spawn_file_actions_init(&item->fa);
	posix_spawn_file_actions_addclose(&item->fa, 0);
	posix_spawn_file_actions_addclose(&item->fa, 1);
	posix_spawn_file_actions_addclose(&item->fa, 2);
	posix_spawn_file_actions_addopen(&item->fa, 0, "/dev/null", O_RDONLY, 0);
	posix_spawn_file_actions_addopen(&item->fa, 1, item->scripts.stdoutfn->ptr, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	posix_spawn_file_actions_adddup2(&item->fa, 1, 2);
	int ret = posix_spawnp(&item->pid, arr[0], &item->fa, NULL, arr, environ);
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
		if(!is_installed(state->installed_packages, stringptrlist_get(item->deps, i))) return 0;

	sblist_iter(state->queue[JT_DOWNLOAD], dlitem) {
		if(EQ(dlitem->name, item->name)) {
			return (dlitem->pid == 0); //download finished?
		}
	}
	return (!stringptrlist_getsize(item->mirrors) || has_tarball(&state->cfg, item));
}

static int queue_empty(sblist* queue) {
	pkg_exec* item;
	sblist_iter(queue, item) {
		if(item->pid != 0)
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
		if(item->pid == -1) {
			pkg = packagelist_get(state->package_list, item->name, stringptr_hash(item->name));
			if(ptype == JT_DOWNLOAD || has_all_deps(state, pkg)) {
				if(ptype == JT_BUILD && !pkg->verified && stringptrlist_getsize(pkg->mirrors)) {
					if (! (pkg->verified = !(verify_tarball(&state->cfg, pkg)))) {
						log_put(2, VARISL("WARNING: "), VARIS(item->name), VARISL(" failed to verify! please delete its tarball and retry downloading it."), NULL);
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
	static const char* queue_names[] = { [JT_DOWNLOAD] = "download", [JT_BUILD] = "build", };
	const char *queuename = queue_names[jt];
	pkg_exec* listitem;
	
	log_put(1, VARISL("*** "), VARICC(queuename), VARISL("queue ***"), NULL);
	sblist_iter(queue, listitem) {
		log_puts(1, listitem->name);
		log_putln(1);
	}
}

static void print_info(pkgstate* state) {
	print_queue(state, JT_DOWNLOAD);
	print_queue(state, JT_BUILD);
}

static void mark_finished(pkgstate* state, stringptr* name) {
	char buf[256];
	if(!stringptrlist_contains(state->installed_packages, name)) {
		ulz_snprintf(buf, sizeof(buf), "%s/pkg/installed.dat", state->cfg.pkgroot.ptr);
		stringptrlist_add(state->installed_packages, stringptr_strdup(name), name->size);
		int fd = open(buf, O_WRONLY | O_CREAT | O_APPEND, 0664);
		if(fd == -1) die(SPL("error couldnt write to installed.dat!"));
		write(fd, name->ptr, name->size);
		write(fd, "\n", 1);
		close(fd);
	}
}

static void warn_errors(pkgstate* state) {
	size_t i;
	stringptr* candidate;
	for(i = 0; i < stringptrlist_getsize(state->build_errors); i++) {
		candidate = stringptrlist_get(state->build_errors, i);
		log_put(2, VARISL("WARNING: "), VARIS(candidate), VARISL(" failed to build! wait for other jobs to finish."), NULL);
	}
}

// TODO: make the two loops into a generic one and put it into a sep. function
static int process_queue(pkgstate* state) {
	int retval, ret;
	pkg_exec* listitem;
	int had_event = 0;
	pkgdata* pkg;
	sblist *queue;
	
	jobtype jt = JT_DOWNLOAD;
	
	// check for finished downloads
	queue = state->queue[jt];
	sblist_iter(queue, listitem) {
		if(listitem->pid && listitem->pid != -1) {
			ret = waitpid(listitem->pid, &retval, WNOHANG);
			if(ret != 0) {
				had_event = 1;
				state->slots[jt].avail++;
				posix_spawn_file_actions_destroy(&listitem->fa);
				if(ret == -1) {
					log_perror("waitpid");
					goto retry;
				}
				if(!retval) {
					pkg = packagelist_get(state->package_list, listitem->name, stringptr_hash(listitem->name));
					ret = verify_tarball(&state->cfg, pkg);
					pkg->verified = !ret;
					if(ret == 1) { // download too small, retry...
						log_put(2, VARISL("retrying too short download of "), VARIS(listitem->name), NULL);
						listitem->pid = -1;
					} else // do not retry on success, hash mismatch or too big file.
						listitem->pid = 0; // 0 means finished.
				}
				else {
					log_put(2, VARISL("got error "), VARII(WEXITSTATUS(retval)), VARISL(" from download script of "), VARIS(listitem->name) ,VARISL(", retrying"), NULL);
					retry:
					listitem->pid = -1; // retry
				}
			}
		}
	}
	
	if(state->slots[jt].avail) fill_slots(jt, state);
	
	jt = JT_BUILD;
	queue = state->queue[jt];
	
	sblist_iter(queue, listitem) {
		if(listitem->pid && listitem->pid != -1) {
			ret = waitpid(listitem->pid, &retval, WNOHANG);
			if(ret != 0) {
				had_event = 1;
				state->slots[jt].avail++;
				posix_spawn_file_actions_destroy(&listitem->fa);
				if(ret == -1) {
					log_perror("waitpid");
					listitem->pid = -1; // retrying;
				} else {
					if(!retval) {
						listitem->pid = 0; // 0 means finished.
						mark_finished(state, listitem->name);
					} else {
						listitem->pid = 0;
						stringptrlist_add(state->build_errors, stringptr_strdup(listitem->name), listitem->name->size);
					}
				}
			}
		}
	}
	
	if(state->slots[jt].avail) fill_slots(JT_BUILD, state);
	
	if(had_event) warn_errors(state);
	
	int done = state->slots[JT_DOWNLOAD].avail == state->slots[JT_DOWNLOAD].max &&
	         state->slots[JT_BUILD].avail == state->slots[JT_BUILD].max;
	
	if(done) {
		if(!(queue_empty(state->queue[JT_DOWNLOAD])) ||
		   !(queue_empty(state->queue[JT_BUILD]))) {
			ulz_fprintf(2, "[WARNING] circular reference detected!");
		}
	}
	
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
		[PKGC_INSTALL] = "install", [PKGC_REBUILD] = "rebuild",
		[PKGC_REBUILD_ALL] = "rebuildall", [PKGC_PREFETCH] = "prefetch",
	};
	
	if(argc < 3) syntax();
	
	for(i = PKGC_NONE + 1; (unsigned) i < ARRAY_SIZE(opt_strings); i++)
		if(!strcmp(argv[1], opt_strings[i]))
			mode = (pkgcommands) i;

	if(mode == PKGC_NONE) syntax();
	
	srand(time(NULL));
	
	getconfig(&state);
	state.installed_packages = stringptrlist_new(64);
	get_installed_packages(&state.cfg, state.installed_packages);
	
	state.package_list = hashlist_new(64, sizeof(pkgdata));
	state.queue[JT_DOWNLOAD] = sblist_new(sizeof(pkg_exec), 64);
	state.queue[JT_BUILD] = sblist_new(sizeof(pkg_exec), 64);
	state.build_errors = stringptrlist_new(4);
	state.checked[JT_DOWNLOAD] = stringptrlist_new(64);
	state.checked[JT_BUILD] = stringptrlist_new(64);
	
	int force[] = { [PKGC_REBUILD] = 1,  [PKGC_REBUILD_ALL] = -1, [PKGC_INSTALL] = 0 };
	stringptr curr;
	for(i=2; i < argc; i++) {
		queue_package(&state, stringptr_fromchar(argv[i], &curr), JT_DOWNLOAD, 0);
		if(mode != PKGC_PREFETCH) 
			queue_package(&state, stringptr_fromchar(argv[i], &curr), JT_BUILD, force[mode]);
	}
	print_info(&state);
	prepare_slots(&state);
	
	while(process_queue(&state)) sleep(1);
	
	int failed = stringptrlist_getsize(state.build_errors) != 0;
	
	// clean up ...
	
	stringptrlist_freeall(state.build_errors);
	stringptrlist_freeall(state.checked[JT_DOWNLOAD]);
	stringptrlist_freeall(state.checked[JT_BUILD]);
	stringptrlist_freeall(state.installed_packages);
	
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
