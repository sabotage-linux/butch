#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <time.h>

#include "../lib/include/stringptrlist.h"
#include "../lib/include/stringptr.h"
#include "../lib/include/strlib.h"
#include "../lib/include/logger.h"
#include "../lib/include/fileparser.h"
#include "../lib/include/iniparser.h"
#include "../lib/include/filelib.h"

#define NUM_DL_THREADS 16
#define NUM_BUILD_THREADS 2

typedef enum {
	PKGC_NONE,
	PKGC_INSTALL,
	PKGC_REBUILD,
	PKGC_PREFETCH
} pkgcommands;

typedef struct {
	stringptr* tardir;
	stringptrlist* deps;
	stringptrlist* mirrors;
	stringptrlist* buildscript;
} pkgdata;

typedef struct {
	stringptr filename;
	stringptr stdoutfn;
} scriptinfo;

typedef struct {
	stringptr name;
	pkgdata data;
	pid_t pid;
	scriptinfo scripts;
} pkg;

typedef struct {
	stringptr installroot;
	stringptr pkgroot;
	stringptr filecache;
	stringptr arch;
	stringptr logdir;
	stringptr keep;
} pkgconfig;

typedef struct {
	int build_slots;
	int dl_slots;
} procslots;


typedef struct {
	pkgconfig cfg;
	stringptrlist* installed_packages;
	sblist* dl_queue;
	sblist* build_queue;
	stringptrlist* build_errors;
	procslots slots;
} pkgstate;

__attribute__((noreturn))
void die(stringptr* message) {
	log_puts(2, message);
	exit(1);
}

void syntax(void) {
	die(SPL("syntax: pkg command options\ncommands: install, rebuild, prefetch\npass an arbitrary number of package names as options\n"));
}

void getconfig(pkgconfig* c) {
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
#undef check_access
}

int get_tarball_filename(pkgdata* package, char* buf, size_t bufsize) {
	if(stringptrlist_getsize(package->mirrors) == 0) return 0;
	ulz_snprintf(buf, bufsize, "%s", getfilename(stringptrlist_get(package->mirrors, 0)));
	return 1;
}

int get_tarball_filename_with_path(pkgconfig* cfg, pkgdata* package, char* buf, size_t bufsize) {
	if(stringptrlist_getsize(package->mirrors) == 0) return 0;
	ulz_snprintf(buf, bufsize, "%s/%s", cfg->filecache.ptr, getfilename(stringptrlist_get(package->mirrors, 0)));
	return 1;
}

void strip_fileext(stringptr* s) {
	char* dot = stringptr_rchr(s, '.');
	*dot = 0;
	s->size = dot - s->ptr;
	if((dot = stringptr_rchr(s, '.')) && !strcmp(dot, ".tar")) {
		s->size = dot - s->ptr;
		*dot = 0;
	}
}

void get_package_contents(pkgconfig* cfg, stringptr* packagename, pkgdata* out) {
	ini_section sec;
	char buf[256];
	ulz_snprintf(buf, sizeof(buf), "%s/pkg/%s", cfg->pkgroot.ptr, packagename->ptr);
	
	
	memset(out, 0, sizeof(pkgdata));
	
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
	
	sec = iniparser_get_section(ini, SPL("deps"));
	out->deps = stringptrlist_new(sec.linecount);
	
	for(start = sec.startline; start < sec.startline + sec.linecount; start++) {
		tmp = stringptrlist_get(ini, start);
		if(tmp->size) stringptrlist_add(out->deps, stringptr_strdup(tmp), tmp->size);
	}
	
	sec = iniparser_get_section(ini, SPL("build")); // the build section has always to come last
	if(sec.linecount) {
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

void get_installed_packages(pkgconfig* cfg, stringptrlist* packages) {
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


int is_installed(stringptrlist* packages, stringptr* packagename) {
	return stringptrlist_contains(packages, packagename);
}

int has_tarball(pkgconfig* cfg, pkgdata* package) {
	char buf[256];
	if(!get_tarball_filename_with_path(cfg, package, buf, sizeof(buf))) goto err;
	return (access(buf, R_OK) != -1);
	err:
	return 0;
}

void free_package_data(pkgdata* data) {
	stringptr_free(data->tardir);
	stringptrlist_free(data->buildscript);
	stringptrlist_free(data->deps);
	stringptrlist_free(data->mirrors);
}

int is_in_queue(stringptr* packagename, sblist* queue) {
	size_t i;
	pkg* listitem;
	for(i = 0; i < sblist_getsize(queue); i++) {
		listitem = sblist_get(queue, i);
		if(EQ(&(listitem->name), packagename))
			return 1;
	}
	return 0;
}

void add_queue(stringptr* packagename, sblist* queue, pkg* data) {
	stringptr* tmp;
	tmp = stringptr_copy(packagename);
	data->pid = (pid_t) -1;
	data->name = *tmp;
	sblist_add(queue, data);
}

void queue_download(pkgstate* state, stringptr* packagename) {
	size_t i;
	pkg data;
	int added = 0;
	
	if(!packagename->size) return;
	if(is_in_queue(packagename, state->dl_queue)) return;

	if(is_installed(state->installed_packages, packagename)) {
		ulz_fprintf(1, "package %s is already installed, skipping download\n", packagename->ptr);
		return;
	}

	get_package_contents(&state->cfg, packagename, &data.data);

	
	// if sizeof mirrors is 0, it is a meta package
	if(stringptrlist_getsize(data.data.mirrors) && !has_tarball(&state->cfg, &data.data)) {
		add_queue(packagename, state->dl_queue, &data);
		added = 1;
	}
	
	for(i = 0; i < stringptrlist_getsize(data.data.deps); i++)
		queue_download(state, stringptrlist_get(data.data.deps, i)); // omg recursion
		
	if(!added) free_package_data(&data.data);
}

void queue_install(pkgstate* state, stringptr* packagename, int force) {
	size_t i;
	pkg data;
	
	if(!packagename->size) return;
	if(is_in_queue(packagename, state->build_queue)) return;
	
	if(!force && is_installed(state->installed_packages, packagename)) {
		ulz_fprintf(1, "package %s is already installed, skipping build\n", packagename->ptr);
		return;
	}
	
	get_package_contents(&state->cfg, packagename, &data.data);
	
	for(i = 0; i < stringptrlist_getsize(data.data.deps); i++)
		queue_install(state, stringptrlist_get(data.data.deps, i), 0); // omg recursion
		
	if(stringptrlist_getsize(data.data.buildscript)) {
		add_queue(packagename, state->build_queue, &data);
	} else 
		free_package_data(&data.data);
}

stringptr* make_config(pkgconfig* cfg) {
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

int create_script(int ptype, pkgstate* state, pkg* item) {
	stringptr* temp, *config, tb;
	char* prefix;
	char buf[256];
	int hastarball;
	if(ptype == 0) {
		prefix = "dl";
	} else if (ptype == 1) {
		prefix = "build";
	} else abort();
	temp = stringptr_format("%s/%s_%s.sh", state->cfg.pkgroot.ptr, prefix, item->name.ptr);
	item->scripts.filename = *temp;
	temp = stringptr_format("%s/%s_%s.log", state->cfg.logdir.ptr, prefix, item->name.ptr); 
	item->scripts.stdoutfn = *temp;
	config = make_config(&state->cfg);
	hastarball = get_tarball_filename(&item->data, buf, sizeof(buf));
	
	if(ptype == 0) {
		if(!hastarball) abort(); //bug
		temp = stringptr_concat(SPL("#!/bin/sh\n"),
			config,
			SPL("wget -c "),
			stringptrlist_get(item->data.mirrors, rand() % stringptrlist_getsize(item->data.mirrors)),
			SPL(" -O $C/"),
			stringptr_fromchar(buf, &tb),
			NULL);
		
	} else if (ptype == 1) {
		stringptr* buildscr = stringptrlist_tostring(item->data.buildscript);
		
		if(!hastarball) {
			temp = stringptr_concat(SPL("#!/bin/sh\n"), 
				config,
				buildscr,
				NULL);
		} else {
			
			temp = stringptr_concat(SPL("#!/bin/sh\n"), 
				config,
				SPL("cd $S\ntar xf $C/"), 
				stringptr_fromchar(buf, &tb),
				SPL("\ncd $S/"),
				item->data.tardir,
				SPL("\n"),
				buildscr,
				NULL);
		}
		
		stringptr_free(buildscr);
		
	} else abort();

	stringptr_tofile(item->scripts.filename.ptr, temp);
	if(chmod(item->scripts.filename.ptr, 0777) == -1) die(SPL("error setting permission"));
	stringptr_free(temp);
	return 1;
}

extern char** environ;

void launch_thread(int ptype, pkgstate* state, pkg* item) {
	posix_spawn_file_actions_t fa;
	char* arr[2];
	create_script(ptype, state, item);
	log_timestamp(1);
	log_putspace(1);
	if(ptype == 0) {
		log_puts(1, SPL("downloading "));
	} else 
		log_puts(1, SPL("building "));

	log_put(1, VARIS(&(item->name)), VARISL("("), VARIS(&(item->scripts.filename)), VARISL(") -> "), VARIS(&(item->scripts.stdoutfn)), NULL);

	arr[0] = item->scripts.filename.ptr;
	arr[1] = NULL;
	
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_addclose(&fa, 0);
	posix_spawn_file_actions_addclose(&fa, 1);
	posix_spawn_file_actions_addclose(&fa, 2);
	posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
	posix_spawn_file_actions_addopen(&fa, 1, item->scripts.stdoutfn.ptr, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	posix_spawn_file_actions_adddup2(&fa, 1, 2);
	int ret = posix_spawnp(&item->pid, arr[0], &fa, NULL, arr, environ);
	if(ret == -1) {
		log_perror("posix_spawn");
		die(SPL(""));
	}
}

static inline size_t min_s(size_t a, size_t b) {
	if (a < b) return a;
	return b;
}

int has_all_deps(pkgstate* state, pkg* item) {
	size_t i;
	pkg* dlitem;
	for(i = 0; i < stringptrlist_getsize(item->data.deps); i++)
		if(!is_installed(state->installed_packages, stringptrlist_get(item->data.deps, i))) return 0;
	for(i = 0; i < sblist_getsize(state->dl_queue); i++) {
		dlitem = sblist_get(state->dl_queue, i);
		if(EQ(&dlitem->name, &item->name)) {
			return (dlitem->pid == 0); //download finished?
		}
	}
	return (!stringptrlist_getsize(item->data.mirrors) || has_tarball(&state->cfg, &item->data));
}

void fill_slots(int ptype, pkgstate* state) {
	size_t i;
	pkg* item;
	int* slots = ptype == 0 ? &state->slots.dl_slots : &state->slots.build_slots;
	sblist* queue = ptype == 0 ? state->dl_queue : state->build_queue;
	for(i = 0; *slots && i < sblist_getsize(queue); i++) {
		item = sblist_get(queue, i);
		if(item->pid == -1) {
			if(ptype == 0 || has_all_deps(state, item)) {
				launch_thread(ptype, state, item);
				(*slots)--;
			}
		}
	}
}

void prepare_queue(pkgstate* state) {
	state->slots.build_slots = NUM_BUILD_THREADS;
	state->slots.dl_slots = NUM_DL_THREADS;
	fill_slots(0, state);
}

void print_info(pkgstate* state) {
	size_t i;
	pkg* listitem;

	log_puts(1, SPL("*** download queue ***\n"));
	for(i = 0; i < sblist_getsize(state->dl_queue); i++) {
		listitem = sblist_get(state->dl_queue, i);
		log_puts(1, &listitem->name);
		log_putln(1);
	}

	log_puts(1, SPL("*** build queue ***\n"));
	for(i = 0; i < sblist_getsize(state->build_queue); i++) {
		listitem = sblist_get(state->build_queue, i);
		log_puts(1, &listitem->name);
		log_putln(1);
	}
}

void mark_finished(pkgstate* state, stringptr* name) {
	char buf[256];
	ulz_snprintf(buf, sizeof(buf), "%s/pkg/installed.dat", state->cfg.pkgroot.ptr);
	stringptrlist_add(state->installed_packages, stringptr_strdup(name), name->size);
	int fd = open(buf, O_WRONLY | O_CREAT | O_APPEND, 0664);
	if(fd == -1) die(SPL("error couldnt write to installed.dat!"));
	write(fd, name->ptr, name->size);
	write(fd, "\n", 1);
	close(fd);
}

void warn_errors(pkgstate* state) {
	size_t i;
	stringptr* candidate;
	for(i = 0; i < stringptrlist_getsize(state->build_errors); i++) {
		candidate = stringptrlist_get(state->build_errors, i);
		log_put(2, VARISL("WARNING: "), VARIS(candidate), VARISL(" failed to build! wait for other jobs to finish."), NULL);
	}
}

int process_queue(pkgstate* state) {
	size_t i;
	int retval, ret;
	pkg* listitem;
	int had_event = 0;
	
	// check for finished downloads
	for(i = 0; i < sblist_getsize(state->dl_queue); i++) {
		listitem = sblist_get(state->dl_queue, i);
		if(listitem->pid && listitem->pid != -1) {
			ret = waitpid(listitem->pid, &retval, WNOHANG);
			if(ret != 0) {
				had_event = 1;
				state->slots.dl_slots++;
				if(ret == -1) {
					log_perror("waitpid");
					goto retry;
				}
				if(!retval) listitem->pid = 0; // 0 means finished.
				else {
					log_put(2, VARISL("got error "), VARII(WEXITSTATUS(retval)), VARISL(" from download script of "), VARIS(&listitem->name) ,VARISL(", retrying"), NULL);
					retry:
					listitem->pid = -1; // retry
				}
			}
		}
	}
	
	if(state->slots.dl_slots) fill_slots(0, state);
	
	for(i = 0; i < sblist_getsize(state->build_queue); i++) {
		listitem = sblist_get(state->build_queue, i);
		if(listitem->pid && listitem->pid != -1) {
			ret = waitpid(listitem->pid, &retval, WNOHANG);
			if(ret != 0) {
				had_event = 1;
				state->slots.build_slots++;
				if(ret == -1) {
					log_perror("waitpid");
					listitem->pid = -1; // retrying;
				} else {
					if(!retval) {
						listitem->pid = 0; // 0 means finished.
						mark_finished(state, &listitem->name);
					} else {
						listitem->pid = 0;
						stringptrlist_add(state->build_errors, stringptr_strdup(&listitem->name), listitem->name.size);
					}
				}
				fill_slots(1, state);
			}
		}
	}
	
	if(state->slots.build_slots) fill_slots(1, state);
	
	if(had_event) warn_errors(state);
	
	return !(state->slots.dl_slots == NUM_DL_THREADS && state->slots.build_slots == NUM_BUILD_THREADS);
}

int main(int argc, char** argv) {
	pkgstate state;
	pkgcommands mode = PKGC_NONE;
	
	if(argc < 3) syntax();
	if(!strcmp(argv[1], "install"))
		mode = PKGC_INSTALL;
	else if(!strcmp(argv[1], "rebuild"))
		mode = PKGC_REBUILD;
	else if(!strcmp(argv[1], "prefetch"))
		mode = PKGC_PREFETCH;
	if(mode == PKGC_NONE) syntax();
	
	srand(time(NULL));
	
	getconfig(&state.cfg);
	state.installed_packages = stringptrlist_new(64);
	get_installed_packages(&state.cfg, state.installed_packages);
	
	
	state.build_queue = sblist_new(sizeof(pkg), 64);
	state.dl_queue = sblist_new(sizeof(pkg), 64);
	state.build_errors = stringptrlist_new(4);
	
	int i;
	stringptr curr;
	for(i=2; i < argc; i++) {
		switch(mode) {
			case PKGC_PREFETCH:
				queue_download(&state, stringptr_fromchar(argv[i], &curr));
				break;
			case PKGC_INSTALL:
				queue_download(&state, stringptr_fromchar(argv[i], &curr));
				queue_install(&state, stringptr_fromchar(argv[i], &curr), 0);
				break;
			case PKGC_REBUILD:
				queue_download(&state, stringptr_fromchar(argv[i], &curr));
				queue_install(&state, stringptr_fromchar(argv[i], &curr), 1);
				break;
				
			default:
				break;
		}
	}
	print_info(&state);
	prepare_queue(&state);
	
	while(process_queue(&state)) sleep(1);
	
	// free contents of all stringptrlists...
	
	return 0;
}
