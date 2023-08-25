#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include "logdigest.h"


/// INDEX
/// SECTION: UTILITY
/// SECTION: API IMPLEMENTATION
/// SECTION: MULTILOG PARSING
/// SECTION: SYSLOG PARSING
/// SECTION: MYSQL PARSING
/// SECTION: WINDOWS EVENT PARSING
/// SECTION: TEST INTERNAL


#ifdef __cplusplus
extern "C" {
#endif


#ifndef LD_BUFSIZE
# include <stdio.h>
# define LD_BUFSIZE           BUFSIZ
#endif

#ifndef LD_ASSERT
# include <assert.h>
# define LD_ASSERT(EXPR)      assert(EXPR)
#endif

#define LD_MAX_WATCHERS        32
#define LD_WATCHER_TIMEOUT_MS  1

// API has multiple implementations for different platforms
#define LD_IMPL

#define LD_UNREACHABLE        LD_ASSERT(0 && "unreachable")
#define LD_INIT_GUARD(MSG)    if (!g.has_called_init) \
								  LD_ASSERT(0 && MSG)

#define MIN(A, B)             ((A) < (B) ? (A) : (B))
#define MAX(A, B)             ((A) > (B) ? (A) : (B))
#define BETWEEN(A, L, R)      ((L) <= (A) && (A) <= (R))
#define COUNT(A)              (sizeof (A) / sizeof *(A))

typedef struct xml_string xml_string_t;
typedef struct xml_attr xml_attr_t;
typedef struct xml_tag xml_tag_t;
typedef struct watcher watcher_t;

// Windows-Only API forward declarations and dependencies
#ifdef LD_PLATFORM_WINDOWS

#include <windows.h>
#include <winevt.h>
#include <minwinbase.h>
#include <ioapiset.h>
#include <fileapi.h>

#pragma comment(lib, "Wevtapi.lib")

static void winevt_init();
static void winevt_shutdown();
static DWORD WINAPI winevt_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);
static DWORD winevt_print_event(EVT_HANDLE hEvent);
static int win_read_directory_changes(watcher_t* w);
static size_t win_get_dir_path(const char* file_path);

#endif // LD_PLATFORM_WINDOWS

struct xml_string {
	const char* pos;
	size_t len;
};

struct xml_attr {
	xml_attr_t* next;
	xml_string_t name;
	xml_string_t value;
};

struct xml_tag {
	xml_tag_t* next;
	xml_attr_t* attr;
	xml_string_t name;
	xml_string_t text;
	xml_tag_t* child;
};

struct watcher {
	int handle;           // watcher identifier, non-negative
	char *path;           // path to observed file
	size_t offset;        // number of bytes already read from file
	ld_log_type type;     // log format type
	FILE *file;

#ifdef LD_PLATFORM_WINDOWS
	HANDLE dir_handle;
	OVERLAPPED overlapped;
	const char* file_name;
#endif
};

static struct global {
	int has_called_init;
	char buf[LD_BUFSIZE];
	watcher_t watchers[LD_MAX_WATCHERS];

	void (*syslog_callback)(ld_syslog_t*);
	void (*multilog_callback)(ld_multilog_t*);

#ifdef LD_PLATFORM_WINDOWS
	void (*winevt_xml_callback)(ld_winevt_xml_t*);

	EVT_HANDLE winevt_subscription;
	char win_watcher_buf[LD_BUFSIZE];
#endif
#ifdef LD_PLATFORM_UNIX
	int ifd; // inotify file descriptor
#endif

} g;

static void* xmalloc(size_t size);
static void xfree(void* mem);
static char* xstrdup(const char* s);
static int is_ascii_printable(char c);
static int skip_space(const char** c);
static int count_space(const char* c);
static int count_alnum(const char* c);
static int wordcpy(char* to, const char* from, int limit);
static int linecpy(char* to, const char* from, int limit);
static xml_tag_t* xml_parse(const char* str, size_t len);
static xml_tag_t* parse_xml_tag(const char **pos);
static int parse_xml_tag_open(const char** pos, xml_tag_t* tag);
static int parse_xml_tag_close(const char** pos, xml_tag_t* tag);
static int parse_xml_tag_attributes(const char** pos, xml_tag_t* tag);
static void xml_free(xml_tag_t* root);
static xml_attr_t* new_xml_attr();
static xml_tag_t* new_xml_tag();
static void dispatch_logs(watcher_t *w, const char *buf, size_t buf_size);
static LD_IMPL void watcher_init();
static LD_IMPL void watcher_shutdown();
static LD_IMPL void watcher_poll();
static LD_IMPL void watcher_add(const char *path, ld_log_type type);
static LD_IMPL void watcher_rm(const char *path);
static size_t watcher_read_to_buf(watcher_t *w, char *buf, size_t buf_size);
static watcher_t *watcher_find_by_path(const char *path);
static watcher_t *watcher_find_by_handle(int handle);
static watcher_t *watcher_alloc_slot();
static void watcher_free_slot(watcher_t *w);
static ld_syslog_t* new_syslog();
static ld_multilog_t* new_multilog();
static ld_winevt_xml_t* new_winevt_xml();
static void free_xml_attr(xml_attr_t* attr);
static void free_xml_tag(xml_tag_t* root);
static void free_syslog(ld_syslog_t *syslog);
static void free_multilog(ld_multilog_t* multilog);
static void free_winevt_xml(ld_winevt_xml_t* winevt);
static int get_syslog_ietf_header(const char** ptr, ld_syslog_t* syslog);
static int get_syslog_bsd_header(const char** ptr, ld_syslog_t* syslog);
static int get_multilog_timestamp(const char** ptr, ld_multilog_t *multilog);


/* TODO: UTF-8 Decoder
static const unsigned char utf8_masks[5] = { 0xC0,     0x80, 0xE0,  0xF0,   0xF8 };
static const unsigned char utf8_bytes[5] = { 0x80,     0x00, 0xC0,  0xE0,   0xF0 };
static const ld_code_t utf8_range_min[5] = { 0,        0,    0x80,  0x800,  0x10000 };
static const ld_code_t utf8_range_max[5] = { 0x10FFFF, 0x7F, 0x7FF, 0xFFFF, 0x10FFFF };
*/


/// SECTION: UTILITY
/// memory allocation wrappers
/// string and numeric utilities
/// UTF-8 decoder
/// XML parser
#pragma region UTILITY

static void* xmalloc(size_t size)
{
	void* chunk = malloc(size);
	LD_ASSERT(chunk && "malloc: returned NULL");

	return chunk;
}

static void xfree(void* chunk)
{
	LD_ASSERT(chunk && "free: attempt to free NULL");
	free(chunk);
}

char* xstrdup(const char* s)
{
	LD_ASSERT(s && strlen(s) > 0 && "attempt to duplicate empty string");
	return strdup(s);
}

static int is_ascii_printable(char c)
{
	return 32 <= c && c <= 126;
}

static int skip_space(const char** c)
{
	int jmp = count_space(*c);
	*c += jmp;
	return jmp;
}

static int count_space(const char* c)
{
	int ctr;
	for (ctr = 0; c && isspace(*c); c++)
		ctr++;
	return ctr;
}

static int count_alnum(const char* c)
{
	int ctr;
	for (ctr = 0; c && isalnum(*c); c++)
		ctr++;
	return ctr;
}

static int count_digits(int num)
{
	int digits = 0;

	do {
		digits++;
		num /= 10;
	} while (num != 0);
	return digits;
}

// word delimiter is whitespace and '\0'
// returns number of bytes copied
// writes maximum of limit + 1 bytes to output with NULL terminator
// input and output buffer should not overlap
static int wordcpy(char* to, const char* from, int limit)
{
	int i;

	for (i = 0; i < limit && from[i] != '\0' && !isspace(from[i]); i++)
		to[i] = from[i];
	to[i] = '\0';

	return i;
}

// line delimiter is '\n' and '\0'
// returns number of bytes copied
// writes maximum of limit + 1 bytes to output with NULL terminator
// input and output buffer should not overlap
int linecpy(char* to, const char* from, int limit)
{
	int i;

	for (i = 0; i < limit && from[i] != '\0' && from[i] != '\n'; i++)
		to[i] = from[i];
	to[i] = '\0';

	return i;
}


// decode a Unicode codepoint from UTF-8 byte stream
// zero-tolerance decoding, does not handle input with wrong UTF-8 encoding
static ld_code_t utf8_decode(const char* s, int* len)
{
	// TODO:
}

static void utf8_decode_byte()
{
	// TODO:
}

// construct a XML document tree from string input
// zero tolerance, does not handle invalid XML input
// xml_string_t does not allocate its own buffer and are only stringviews of the input string
// therefore the lifetime of input string MUST be longer than the lifetime of output XML document
static xml_tag_t* xml_parse(const char* str, size_t len)
{
	xml_tag_t dummy = { .next = NULL };
	xml_tag_t* child = &dummy;

	if (!str || len == 0)
		return NULL;

	xml_tag_t* root = new_xml_tag();
	while ((child = child->next = parse_xml_tag(&str))) ;
	root->child = dummy.next;

	return root;
}

static void xml_free(xml_tag_t* root)
{
	if (root)
		free_xml_tag(root);
}

static int xml_strcmp(xml_string_t* str, const char* cstr)
{
	return strncmp(cstr, str->pos, str->len);
}

// recursively parse a tag and its children
// <tagname attr='value'>content</tagname>
static xml_tag_t* parse_xml_tag(const char **pos)
{
	const char* p = *pos;
	xml_tag_t* tag = new_xml_tag();
	xml_tag_t dummy = { .next = NULL };
	xml_tag_t* child = &dummy;

	if (!parse_xml_tag_open(&p, tag))
		goto fail;

	skip_space(&p);
	
	// self closing tag
	if (*p == '/') {
		p++;
		if (*p++ != '>')
			goto fail;
		*pos = p;
		return tag;
	}

	if (*p++ != '>')
		goto fail;

	// parse content before closing tag
	// content should either be a string of text or
	// one or more xml children tags
	skip_space(&p);
	while (!(p[0] == '<' && p[1] == '/')) {
		if (*p == '<')
			child = child->next = parse_xml_tag(&p);
		else {
			const char* q = strchr(p, '<');
			tag->text.pos = p;
			tag->text.len = q - p;
			p = q;
			LD_ASSERT(p[0] == '<' && p[1] == '/');
		}
	}
	
	parse_xml_tag_close(&p, tag);

	*pos = p;
	tag->child = dummy.next;
	return tag;

fail:
	free_xml_tag(tag);
	return NULL;
}

// parse the opening tag, scan for tag name and attributes
// <tagname attr1='value1' attr2='value2'
static int parse_xml_tag_open(const char** pos, xml_tag_t* tag)
{
	skip_space(pos);
	const char* p = *pos;

	if (*p++ != '<' || isspace(*p))
		return 0;

	tag->name.pos = p;
	tag->name.len = count_alnum(p);
	p += tag->name.len;

	parse_xml_tag_attributes(&p, tag);

	*pos = p;
	return 1;
}

// parse the closing tag:
// </tagname>
static int parse_xml_tag_close(const char** pos, xml_tag_t* tag)
{
	skip_space(pos);
	const char* p = *pos;
	int i;

	if (*p++ != '<' || *p++ != '/')
		return 0;

	for (i = 0; isalnum(p[i]); i++)
		g.buf[i] = p[i];
	p += i;

	if (strncmp(g.buf, tag->name.pos, tag->name.len))
		return 0;

	if (*p++ != '>')
		return 0;

	*pos = p;
	return 1;
}

int parse_xml_tag_attributes(const char** pos, xml_tag_t* tag)
{
	skip_space(pos);
	const char* p = *pos, *q;
	xml_attr_t dummy = { .next = NULL };
	xml_attr_t* attr = &dummy;
	size_t len;

	while (*p != '>' && isalnum(*p)) {
		attr = attr->next = new_xml_attr();
		q = strchr(p, '=');
		len = q - p;
		attr->name.pos = p;
		attr->name.len = len;
		p += len + 1;
		if (*p != '\'' && *p != '"')
			goto fail;
		for (q = ++p; *q != '\'' && *q != '"'; q++);
		len = q - p;
		attr->value.pos = p;
		attr->value.len = len;
		p += len + 1;
		skip_space(&p);
	}

	*pos = p;
	tag->attr = dummy.next;
	return 1;
fail:
	if (dummy.next)
		free_xml_attr(dummy.next);
	return 0;
}

static xml_attr_t* new_xml_attr()
{
	xml_attr_t* attr = xmalloc(sizeof(xml_attr_t));
	memset(attr, 0, sizeof(xml_attr_t));

	return attr;
}

static xml_tag_t* new_xml_tag()
{
	xml_tag_t* tag = xmalloc(sizeof(xml_tag_t));
	memset(tag, 0, sizeof(xml_tag_t));

	return tag;
}

static void free_xml_attr(xml_attr_t* attr)
{
	LD_ASSERT(attr);

	if (attr->next)
		free_xml_attr(attr->next);

	xfree(attr);
}

static void free_xml_tag(xml_tag_t *root)
{
	LD_ASSERT(root);

	if (root->child)
		free_xml_tag(root->child);

	if (root->next)
		free_xml_tag(root->next);

	if (root->attr)
		free_xml_attr(root->attr);

	xfree(root);
}

#pragma endregion


/// SECTION: API IMPLEMENTATION
/// logdigest.h public API
/// cross-platform file watcher API
#pragma region API_IMPLEMENTATION


// frees the return value of ld_parse_*
void ld_free(ld_log_t* log)
{
	// deallocate common header fields
	if (log->origin)
		xfree((void*)log->origin);

	switch (log->type) {
	case LD_TYPE_SYSLOG:
		free_syslog((ld_syslog_t*)log);
		break;
	case LD_TYPE_MULTILOG:
		free_multilog((ld_multilog_t*)log);
		break;
	case LD_TYPE_WINEVT_XML:
		free_winevt_xml((ld_winevt_xml_t*)log);
		break;
	default:
		// TODO: warning
		LD_UNREACHABLE;
		break;
	}
}

int ld_init()
{
#ifdef LD_PLATFORM_WINDOWS
	// winevt_init();
#endif

	g.syslog_callback = NULL;
	g.multilog_callback = NULL;

	watcher_init();

	g.has_called_init = 1;
	return 1;
}

void ld_shutdown()
{
	if (!g.has_called_init)
		return;
	g.has_called_init = 0;

	watcher_shutdown();

#ifdef LD_PLATFORM_WINDOWS
	// winevt_shutdown();
#endif
}

void ld_watch_syslog(const char* path)
{
	LD_INIT_GUARD("called ld_watch_syslog before ld_init");

	watcher_add(path, LD_TYPE_SYSLOG);
}

void ld_watch_multilog(const char *path)
{
	LD_INIT_GUARD("called ld_watch_multilog before ld_init");

	watcher_add(path, LD_TYPE_MULTILOG);
}

void ld_set_syslog_callback( void(*callback)(ld_syslog_t*) )
{
	LD_INIT_GUARD("called ld_set_syslog_callback before ld_init");

	g.syslog_callback = callback;
}

void ld_set_multilog_callback( void(*callback)(ld_multilog_t*) )
{
	LD_INIT_GUARD("called ld_set_multilog_callback before ld_init");

	g.multilog_callback = callback;
}

void ld_poll()
{
	LD_INIT_GUARD("called ld_poll before ld_init");

	watcher_poll();	
}

static void dispatch_logs(watcher_t *w, const char *buf, size_t buf_size)
{
	static char logbuf[LD_BUFSIZE];
	const char *pos = buf;

	skip_space(&pos);

	// printf("dispatch_logs %p (%lu bytes)\n", buf, buf_size);

	while (pos < buf + buf_size) {
		skip_space(&pos);

		size_t buf_rem = buf_size - (pos - buf);
		pos += linecpy(logbuf, pos, buf_rem);

		switch (w->type) {
			case LD_TYPE_SYSLOG: {
				if (!g.syslog_callback)
					break;

				ld_syslog_t *log = ld_parse_syslog(logbuf);
				if (log) {
					// dispatch with user defined syslog callback
					log->origin = xstrdup(w->path);
					g.syslog_callback(log);
					ld_free((ld_log_t*)log);
				}
				break;
			}
			case LD_TYPE_MULTILOG: {
				if (!g.multilog_callback)
					break;

				ld_multilog_t *log = ld_parse_multilog(logbuf);
				if (log) {
					// dispatch with user defined multilog callback
					log->origin = xstrdup(w->path);
					g.multilog_callback(log);
					ld_free((ld_log_t*)log);
				}
				break;
			}
			/*
			case LD_TYPE_WINEVT_XML: {
				break;
			}
			*/
			default:
				LD_UNREACHABLE;
		}
	}
}

#ifdef LD_PLATFORM_WINDOWS


// TODO: windows file watching api
static void watcher_init()
{
	for (int i = 0; i < LD_MAX_WATCHERS; i++)
		g.watchers[i].handle = -1;
}

static void watcher_shutdown()
{
	for (int i = 0; i < LD_MAX_WATCHERS; i++)
		if (g.watchers[i].handle > 0)
			watcher_rm(g.watchers[i].path);
}

static void watcher_poll()
{
	DWORD timeout_ms = LD_WATCHER_TIMEOUT_MS;
	DWORD result, num_bytes;
	BOOL overlapped_result;
	FILE_NOTIFY_INFORMATION* info;
	wchar_t wbuf[128];

	for (int i = 0; i < LD_MAX_WATCHERS; i++) {
		watcher_t* w = g.watchers + i;
		if (w->handle < 0)
			continue;

		// non-blocking polling
		result = WaitForSingleObject(w->overlapped.hEvent, timeout_ms);
		switch (result) {
		case WAIT_OBJECT_0:
			// printf("watcher poll: %d\n", w->handle);
			overlapped_result = GetOverlappedResult(w->dir_handle, &w->overlapped, &num_bytes, FALSE);
			LD_ASSERT(overlapped_result != 0);

			info = (FILE_NOTIFY_INFORMATION*)g.win_watcher_buf;

			for (;;) {

				DWORD name_len = info->FileNameLength / sizeof(wchar_t);
				LD_ASSERT(name_len < COUNT(wbuf));
				mbstowcs(wbuf, w->file_name, COUNT(wbuf));
				if (wcscmp(info->FileName, wbuf) != 0)
					break;
				
				size_t len = watcher_read_to_buf(w, g.buf, sizeof(g.buf));
				
				// TODO: decouple log dispatch logic from watcher polling logic
				dispatch_logs(w, g.buf, len);

				if (!info->NextEntryOffset)
					break;
				
				*((unsigned char**)&info) += info->NextEntryOffset;
			}
			break;
		case WAIT_TIMEOUT:
			// printf("watcher_poll %d timeout\n", w->handle);
			break;
		default:
			break;
		}

		// we can poll asynchronously again later with watcher_poll
		win_read_directory_changes(w);
	}
}

static void watcher_add(const char* path, ld_log_type type)
{
	static int win_watcher_ctr = 1;
	char* dir_path, *file_name;
	DWORD share, flags;
	size_t dir_path_len;
	watcher_t* w;

	// get windows directory path
	dir_path_len = win_get_dir_path(path);
	dir_path = xmalloc(dir_path_len + 1);
	strncpy(dir_path, path, dir_path_len);
	dir_path[dir_path_len] = '\0';

	// get windows file name
	LD_ASSERT(dir_path_len + 1 < strlen(path));
	file_name = xstrdup(path + dir_path_len + 1);

	fprintf(stderr, "%s watch %s %s\n", __func__, dir_path, file_name);


	share = FILE_SHARE_READ |
		    FILE_SHARE_WRITE |
		    FILE_SHARE_DELETE;
	flags = FILE_FLAG_BACKUP_SEMANTICS |
			FILE_FLAG_OVERLAPPED; // required for async ReadDirectoryChangesW


	w = watcher_alloc_slot();
	w->dir_handle = CreateFile(dir_path, FILE_LIST_DIRECTORY, share, NULL, OPEN_EXISTING, flags, NULL);
	w->overlapped.hEvent = CreateEvent(NULL, FALSE, 0, NULL);
	w->path = xstrdup(path);
	w->type = type;
	w->handle = win_watcher_ctr++;
	w->file_name = file_name;
	w->file = NULL;

	xfree(dir_path);
	int result = win_read_directory_changes(w);
	
	LD_ASSERT(w->dir_handle != INVALID_HANDLE_VALUE);
	LD_ASSERT(result != 0);
}

static void watcher_rm(const char* path)
{
	watcher_t* w = watcher_find_by_path(path);
	LD_ASSERT(w);

	xfree(w->file_name);
	xfree(w->path);
	DeleteFile(w->dir_handle);

	watcher_free_slot(w);
}

#endif // LD_PLATFORM_WINDOWS
#ifdef    LD_PLATFORM_UNIX
#include <sys/select.h>
#include <sys/inotify.h>
#include <sys/time.h>
#include <unistd.h>

static void watcher_init()
{
	for (int i = 0; i < LD_MAX_WATCHERS; i++) {
		g.watchers[i].handle = -1;
		g.watchers[i].file = NULL;
	}

	g.ifd = inotify_init();	
	if (g.ifd < 0)
		perror("inotify");
}

static void watcher_shutdown()
{
	for (int i = 0; i < LD_MAX_WATCHERS; i++) {
		if (g.watchers[i].file)
			watcher_rm(g.watchers[i].path);
	}
}

static void watcher_poll()
{
	static char eventbuf[LD_BUFSIZE];
	struct timeval timeout;
	fd_set rfds;

	FD_ZERO(&rfds);
	FD_SET(g.ifd, &rfds);
	timeout.tv_sec = 0;
	timeout.tv_usec = LD_WATCHER_TIMEOUT_MS * 1000;
	int res = select(FD_SETSIZE, &rfds, NULL, NULL, &timeout);

	if (!FD_ISSET(g.ifd, &rfds))
		return;

	// inotify polling reads from a file descriptor.
	// we match the inotify_events with our log watchers
	// to figure out the type of the new log entries and dispatch them
	size_t bytes_read = read(g.ifd, eventbuf, sizeof(eventbuf));

	for (size_t bytes = 0; bytes < bytes_read; bytes += sizeof(struct inotify_event)) {
		struct inotify_event *event = (struct inotify_event *)(eventbuf + bytes);

		watcher_t *w = watcher_find_by_handle(event->wd);
		LD_ASSERT(w != NULL);

		size_t len = watcher_read_to_buf(w, g.buf, sizeof(g.buf));

		// TODO: decouple log dispatch logic from watcher polling logic
		dispatch_logs(w, g.buf, len);
	}
}

static void watcher_add(const char *path, ld_log_type type)
{
	int wfd = inotify_add_watch(g.ifd, path, IN_MODIFY);
	if (wfd < 0) {
		fprintf(stderr, "inotify_add_watch failed for %s\n", path);
		perror("inotify");
	}

	watcher_t *w = watcher_alloc_slot();
	w->handle = wfd;
	w->path = strdup(path);
	w->file = NULL;
	w->type = type;
}

static void watcher_rm(const char* path)
{
	watcher_t *w = watcher_find_by_path(path);

	if (!w) {
		// TODO: warning
		return;
	}

	inotify_rm_watch(g.ifd, w->handle);
	xfree(w->path);
	if (w->file)
		fclose(w->file);
	watcher_free_slot(w);
}

#endif // LD_PLATFORM_UNIX

static size_t watcher_read_to_buf(watcher_t *w, char *buf, size_t buf_size)
{
	LD_ASSERT(w->handle != -1);
	LD_ASSERT(w->file == NULL);


	w->file = fopen(w->path, "r");
	if (!w->file)
		perror("failed to open file");

	fseek(w->file, 0, SEEK_END);
	size_t file_size = ftell(w->file);

	if (file_size <= w->offset) {
		// TODO: handle file shrinking
		fclose(w->file);
		w->file = NULL;
		return 0;
	}

	size_t bytes_to_read = file_size - w->offset;
	if (bytes_to_read > buf_size)
		LD_ASSERT(0 && "watcher_read_to_buf: input chunk too large");

	fseek(w->file, w->offset, SEEK_SET);
	size_t bytes_read = fread(buf, 1, bytes_to_read, w->file);

	fclose(w->file);
	w->file = NULL;
	w->offset += bytes_read;

	return bytes_read;
}

static watcher_t *watcher_find_by_path(const char *path)
{
	int i; 

	for (i = 0; i < LD_MAX_WATCHERS; i++) {
		watcher_t *w = g.watchers + i;
		if (w->handle != -1 && strncmp(w->path, path, strlen(path)) == 0)
			return w;
	}

	return NULL;
}

static watcher_t *watcher_find_by_handle(int handle)
{
	int i;

	if (handle < 0)
		return NULL;

	for (i = 0; i < LD_MAX_WATCHERS; i++) {
		watcher_t *w = g.watchers + i;
		if (w->handle != -1 && w->handle == handle)
			return w;
	}

	return NULL;
}

static watcher_t* watcher_alloc_slot()
{
	int i;

	for (i = 0; i < COUNT(g.watchers); i++)
		if (g.watchers[i].handle == -1) // empty slot	
			break;

	// TODO: error handling instead of exit()
	if (i == LD_MAX_WATCHERS)
		LD_ASSERT(0 && "watcher_add: ran out of watchers");

	return g.watchers + i;
}

static void watcher_free_slot(watcher_t* w)
{
	w->handle = -1;
}

#pragma endregion
/// SECTION: MULTILOG PARSING
/// multilog is a log rotation utility from Daemontools
/// multilog entries without a valid timestamp is rejected by our parser
/// https://cr.yp.to/daemontools/multilog.html
#pragma region MULTILOG_PARSING

ld_multilog_t* ld_parse_multilog(const char* src)
{
	ld_multilog_t* multilog = new_multilog();

	if (!get_multilog_timestamp(&src, multilog))
		goto fail;

	src += count_space(src);
	if (*src == '\0')
		goto fail;
	
	linecpy(g.buf, src, LD_BUFSIZE);

	multilog->msg = xstrdup(g.buf);
	return multilog;

fail:
	free_multilog(multilog);
	return NULL;
}

static ld_multilog_t* new_multilog()
{
	ld_multilog_t* multilog = xmalloc(sizeof(ld_multilog_t));
	memset(multilog, 0, sizeof(ld_multilog_t));
	multilog->type = LD_TYPE_MULTILOG;

	return multilog;
}

static void free_multilog(ld_multilog_t* multilog)
{
	// free heap allocated fields
	if (multilog->timestamp)
		xfree(multilog->timestamp);

	xfree(multilog);
}

// returns 1 if timestamp is valid, 0 otherwise
// if successfull, ptr now points to one char after the timestamp
int get_multilog_timestamp(const char** ptr, ld_multilog_t* multilog)
{
	// multilog tai64n timestamp format looks something like:
	// @400000003b4a39c23294b13c ...

	const char *c = *ptr;
	char *timestamp = NULL;
	c += count_space(c);
	if (!c || *c != '@')
		goto fail;

	timestamp = xmalloc(26);
	wordcpy(timestamp, c, 25);


	for (int i = 1; i < 25; i++)
		if (!isalnum(c[i]))
			goto fail;

	c += 25;
	if (*c != '\0' && !isspace(*c))
		goto fail;

	*ptr = c;
	multilog->timestamp = timestamp;
	return 1;

fail:
	if (timestamp)
		xfree(timestamp);
	return 0;
}


#pragma endregion
/// SECTION: SYSLOG PARSING
/// handle IETF syslog format
/// handle  BSD syslog format
#pragma region SYSLOG_PARSING


// There are two common standard syslog formats: IETF & BSD
// we handle both and extract important fields into ld_syslog_t
// other syslog formats are ignored.
// IETF Syslog https://www.rfc-editor.org/rfc/rfc5424#section-6
//  BSD Syslog https://www.rfc-editor.org/rfc/rfc3164#section-4
ld_syslog_t* ld_parse_syslog(const char* src)
{
	ld_syslog_t* syslog = new_syslog();

	if (get_syslog_ietf_header(&src, syslog)) {
		// TODO: parse remaining ietf fields

	} // else if (get_syslog_bsd_header(&src, syslog)) {
		// TODO: parse remaining bsd fields
	// TODO: ossec syslog format
	// https://www.ossec.net/docs/docs/manual/output/syslog-output.html
	else {
		free_syslog(syslog);
		return NULL;
	}

	return syslog;
}

static ld_syslog_t *new_syslog()
{
	ld_syslog_t* syslog = xmalloc(sizeof(ld_syslog_t));
	memset(syslog, 0, sizeof(ld_syslog_t));
	syslog->type = LD_TYPE_SYSLOG;

	return syslog;
}

static void free_syslog(ld_syslog_t* syslog)
{
	// free heap allocated fields
	if (syslog->timestamp)
		xfree(syslog->timestamp);
	if (syslog->hostname)
		xfree(syslog->hostname);
	if (syslog->appname)
		xfree(syslog->appname);
	if (syslog->procid)
		xfree(syslog->procid);
	if (syslog->msgid)
		xfree(syslog->msgid);

	xfree(syslog);
}

// returns 1 if header is IETF-compliant, 0 otherwise.
// if successfull, ptr now points to one char after the header,
// and all syslog header fields are filled.
static int get_syslog_ietf_header(const char** ptr, ld_syslog_t* syslog)
{
	const char* c = *ptr;
	char* timestamp = NULL;
	char* hostname = NULL;
	char* appname = NULL;
	char* procid = NULL;
	char* msgid = NULL;
	int priority;
	int version;
	int len;

	// NOTE: IETF header part is always 7-bit ascii,
	//       message part may be UTF-8

	c += count_space(c);
	if (!c || *c++ != '<' || !isdigit(*c))
		goto fail;

	// parse priority
	priority = atoi(c);
	c += count_digits(priority);
	if (!c || *c++ != '>')
		goto fail;

	// parse version
	version = atoi(c);
	c += count_digits(version);
	if (!c)
		goto fail;
	
	// parse timestamp
	c += count_space(c);
	len = wordcpy(g.buf, c, sizeof(g.buf));
	c += len;
	if (len == 0 || !c)
		goto fail;
	timestamp = xstrdup(g.buf);

	// parse hostname
	c += count_space(c);
	len = wordcpy(g.buf, c, sizeof(g.buf));
	c += len;
	if (len == 0 || !c)
		goto fail;
	hostname = xstrdup(g.buf);

	// parse appname
	c += count_space(c);
	len = wordcpy(g.buf, c, sizeof(g.buf));
	c += len;
	if (len == 0 || !c)
		goto fail;
	appname = xstrdup(g.buf);

	// parse procid
	c += count_space(c);
	len = wordcpy(g.buf, c, sizeof(g.buf));
	c += len;
	if (len == 0 || !c)
		goto fail;
	procid = strcmp(g.buf, "-") == 0 ? NULL : xstrdup(g.buf);

	// parse msgid
	c += count_space(c);
	len = wordcpy(g.buf, c, sizeof(g.buf));
	c += len;
	if (len == 0 || !c)
		goto fail;
	msgid = strcmp(g.buf, "-") == 0 ? NULL : xstrdup(g.buf);

	// valid header
	*ptr = c;
	syslog->pri = priority;
	syslog->version = version;
	syslog->timestamp = timestamp;
	syslog->hostname = hostname;
	syslog->appname = appname;
	syslog->procid = procid;
	syslog->msgid = msgid;
	return 1;

fail:
	if (timestamp)
		xfree(timestamp);
	if (hostname)
		xfree(hostname);
	if (appname)
		xfree(appname);
	if (procid)
		xfree(procid);
	if (msgid)
		xfree(msgid);
	return 0;
}

// returns 1 if header is BSD-compliant, 0 otherwise.
// if successfull, ptr now points to one char after the header,
// and all syslog header fields are filled.
static int get_syslog_bsd_header(const char** ptr, ld_syslog_t* syslog)
{
	// <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick
	// on / dev / pts / 8

	// TODO:

	// valid header
	return 1;
}

#pragma endregion
/// SECTION: MYSQL PARSING
/// mysql log formats
#pragma region MYSQL_PARSING

// TODO: mysql binlog
// 
// # at 141
// #100309  9:28 : 36 server id 123  end_log_pos 245
// Query thread_id = 3350  exec_time = 11  error_code = 0

#pragma endregion
/// SECTION: WINDOWS EVENT PARSING
/// subscribe to windows event channel for events
#pragma region WINDOWS_EVENT_CHANNEL

ld_winevt_xml_t* ld_parse_winevt_xml(const char* src)
{
	xml_tag_t* root, *event;
	xml_tag_t* sys, * provider, * eventid, * version, * level, * task, * opcode, * keywords, * timecreated;
	xml_tag_t* eventrecordid, * correlation, * execution, * channel, * computer, * security;
	xml_attr_t* attr;
	ld_winevt_xml_t* winevt = new_winevt_xml();
		
	root = xml_parse(src, strlen(src));

	if (!root || !(event = root->child) || xml_strcmp(&event->name, "Event") != 0)
		goto fail;

	sys = event->child;
	if (!sys || xml_strcmp(&sys->name, "System") != 0)
		goto fail;

	provider = sys->child;
	if (provider && xml_strcmp(&provider->name, "Provider") == 0) {
		attr = provider->attr;
		if (xml_strcmp(&attr->name, "Name") == 0)
			; // extraction site
		else goto fail;
		attr = attr->next;
		if (xml_strcmp(&attr->name, "Guid") == 0)
			; // extraction site
		else goto fail;
		attr = attr->next;
		if (xml_strcmp(&attr->name, "EventSourceName") == 0)
			; // extraction site
		else goto fail;
		if (attr->next != NULL)
			goto fail;
	} else goto fail;

	eventid = provider->next;
	if (eventid && xml_strcmp(&eventid->name, "EventID") == 0) {
		winevt->eventid = atoi(eventid->text.pos);
		attr = eventid->attr;
		if (xml_strcmp(&attr->name, "Qualifiers") == 0)
			; // extraction site
		else goto fail;
	} else goto fail;

	version = eventid->next;
	if (version && xml_strcmp(&version->name, "Version") == 0) {
		winevt->version = atoi(version->text.pos);
	} else goto fail;

	level = version->next;
	if (level && xml_strcmp(&level->name, "Level") == 0) {
		winevt->level = atoi(level->text.pos);
	} else goto fail;

	task = level->next;
	if (task && xml_strcmp(&task->name, "Task") == 0) {
		; // extraction site
	} else goto fail;

	opcode = task->next;
	if (opcode && xml_strcmp(&opcode->name, "Opcode") == 0) {
		winevt->opcode = atoi(opcode->text.pos);
	} else goto fail;

	keywords = opcode->next;
	if (keywords && xml_strcmp(&keywords->name, "Keywords") == 0) {
		; // extraction site
	} else goto fail;

	timecreated = keywords->next;
	if (timecreated && xml_strcmp(&timecreated->name, "TimeCreated") == 0) {
		attr = timecreated->attr;
		if (xml_strcmp(&attr->name, "SystemTime") == 0)
			; // extraction site
		else goto fail;
		if (attr->next != NULL)
			goto fail;
	} else goto fail;

	eventrecordid = timecreated->next;
	if (eventrecordid && xml_strcmp(&eventrecordid->name, "EventRecordID") == 0) {
		winevt->recordid = atoi(eventrecordid->text.pos);
	} else goto fail;

	correlation = eventrecordid->next;
	if (!correlation || xml_strcmp(&correlation->name, "Correlation") != 0)
		goto fail;

	execution = correlation->next;
	if (execution && xml_strcmp(&execution->name, "Execution") == 0) {
		attr = execution->attr;
		if (attr && xml_strcmp(&attr->name, "ProcessID") == 0) {
			; // extraction site
		} else goto fail;
		attr = attr->next;
		if (attr && xml_strcmp(&attr->name, "ThreadID") == 0) {
			; // extraction site
		} else goto fail;
	} else goto fail;

	channel = execution->next;
	if (!channel || xml_strcmp(&channel->name, "Channel") != 0)
		goto fail;

	computer = channel->next;
	if (!computer || xml_strcmp(&computer->name, "Computer") != 0)
		goto fail;

	security = computer->next;
	if (!security || xml_strcmp(&security->name, "Security") != 0)
		goto fail;

	// TODO: event data extraction

	xml_free(root);
	
	return winevt;

fail:
	free_winevt_xml(winevt);
	return NULL;
}

static ld_winevt_xml_t* new_winevt_xml()
{
	ld_winevt_xml_t* winevt = xmalloc(sizeof(ld_winevt_xml_t));
	memset(winevt, 0, sizeof(ld_winevt_xml_t));
	winevt->type = LD_TYPE_WINEVT_XML;

	return winevt;
}

static void free_winevt_xml(ld_winevt_xml_t* winevt)
{

	// TODO: free heap allocated fields
	
	xfree(winevt);
}


// Windows Event Channel
// subscription and callback setups
#ifdef LD_PLATFORM_WINDOWS

static void winevt_init()
{
	DWORD status = ERROR_SUCCESS;
	LPWSTR pwsPath = L"Application";
	LPWSTR pwsQuery = L"*";

	g.winevt_subscription = EvtSubscribe(
		NULL,
		NULL,
		pwsPath,
		pwsQuery,
		NULL,
		NULL,
		winevt_callback,
		EvtSubscribeStartAtOldestRecord
	);

	if (!g.winevt_subscription) {
		status = GetLastError();
		if (status == ERROR_EVT_CHANNEL_NOT_FOUND)
			wprintf(L"Windows Event Channel not found: %s\n", pwsPath);
		else if (status == ERROR_EVT_INVALID_QUERY)
			wprintf(L"Windows Event Channel invalid query: %s\n", pwsQuery);
		else
			wprintf(L"EvtSubscribe failed with status %d\n", status);
	}
}

static void winevt_shutdown()
{
	if (g.winevt_subscription)
		EvtClose(g.winevt_subscription);

	g.winevt_subscription = NULL;
}

static DWORD WINAPI winevt_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent)
{
	UNREFERENCED_PARAMETER(pContext);

	DWORD status = ERROR_SUCCESS;

	switch (action)
	{
		// You should only get the EvtSubscribeActionError action if your subscription flags 
		// includes EvtSubscribeStrict and the channel contains missing event records.
	case EvtSubscribeActionError:
		if (ERROR_EVT_QUERY_RESULT_STALE == (DWORD)hEvent)
		{
			wprintf(L"The subscription callback was notified that event records are missing.\n");
			// Handle if this is an issue for your application.
		}
		else
		{
			wprintf(L"The subscription callback received the following Win32 error: %lu\n", (DWORD)hEvent);
		}
		break;

	case EvtSubscribeActionDeliver:
		if (ERROR_SUCCESS != (status = winevt_print_event(hEvent)))
		{
			goto cleanup;
		}
		break;

	default:
		wprintf(L"SubscriptionCallback: Unknown action.\n");
	}

cleanup:

	if (ERROR_SUCCESS != status)
	{
		// End subscription - Use some kind of IPC mechanism to signal
		// your application to close the subscription handle.
	}

	return status; // The service ignores the returned status.
}

static DWORD winevt_print_event(EVT_HANDLE hEvent)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwBufferSize = 0;
	DWORD dwBufferUsed = 0;
	DWORD dwPropertyCount = 0;
	LPWSTR pRenderedContent = NULL;

	// The EvtRenderEventXml flag tells EvtRender to render the event as an XML string.
	if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
	{
		if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
		{
			dwBufferSize = dwBufferUsed;
			pRenderedContent = (LPWSTR)xmalloc(dwBufferSize);
			EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
		}

		if (ERROR_SUCCESS != (status = GetLastError()))
		{
			wprintf(L"EvtRender failed with %d\n", GetLastError());
			goto cleanup;
		}
	}

	wprintf(L"winevt_print_event\n%s", pRenderedContent);

cleanup:

	if (pRenderedContent)
		xfree(pRenderedContent);

	return status;
}

static int win_read_directory_changes(watcher_t *w)
{
	LD_ASSERT(w && w->handle != -1);
	LD_ASSERT(w->dir_handle != INVALID_HANDLE_VALUE);

	BOOL success = ReadDirectoryChangesW(
		w->dir_handle,
		g.win_watcher_buf,
		sizeof(g.win_watcher_buf),
		FALSE,
		FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
		NULL,
		&w->overlapped,
		NULL
	);

	return (int)success;
}

// get windows directory path from full file path
// file path is  D:\Logs\foo.log
// dir path is   D:\Logs
// dir path is a substring of file path, return its length
static size_t win_get_dir_path(const char* file_path)
{
	size_t dir_path_len;
	char *path = xstrdup(file_path);
	char *pos = path, *next;

	next = strtok(pos, "\\");
	while (next) {
		pos = next;
		next = strtok(NULL, "\\");
	}

	dir_path_len = pos - path - 1;
	xfree(path);
	return dir_path_len;
}


#endif // LD_PLATFORM_WINDOWS

#pragma endregion
/// SECTION: TEST INTERNAL
/// white-box testing of internal utilities and results
#pragma region TEST INTERNAL

#ifdef LD_TEST_INTERNAL

#include "test.h"

static void test_internal_string_ops()
{
	printf("- test string ops\n");

	CHECK_INT(count_space(""), 0);
	CHECK_INT(count_space("\t\tAAA\n"), 2);
	CHECK_INT(count_space("  \nBB\n"), 3);
	CHECK_INT(count_space("\t \n \t \n"), 7);

	CHECK_INT(count_digits(-123), 3);
	CHECK_INT(count_digits(-1), 1);
	CHECK_INT(count_digits(0), 1);
	CHECK_INT(count_digits(1), 1);
	CHECK_INT(count_digits(169), 3);
	CHECK_INT(count_digits(123456789), 9);
	
	char buf[32];
	const char* s1 = "string has 4 words";
	CHECK_INT(wordcpy(buf, s1, sizeof(buf)), 6);
	CHECK_INT(strcmp(buf, "string"), 0);
	CHECK_INT(wordcpy(buf, s1 + 6, sizeof(buf)), 0);
	CHECK_INT((int)strlen(buf), 0);
	CHECK_INT(wordcpy(buf, s1 + 7, sizeof(buf)), 3);
	CHECK_INT(strcmp(buf, "has"), 0);
	CHECK_INT(wordcpy(buf, s1 + 11, sizeof(buf)), 1);
	CHECK_INT(strcmp(buf, "4"), 0);
	const char* s2 = "longstring\nwithnewline";
	CHECK_INT(wordcpy(buf, s2, sizeof(buf)), 10);
	CHECK_INT(strcmp(buf, "longstring"), 0);
	CHECK_INT(wordcpy(buf, s2 + 11, sizeof(buf)), 11);
	CHECK_INT(strcmp(buf, "withnewline"), 0);
	CHECK_INT(wordcpy(buf, s2, 4), 4);
	CHECK_INT(strcmp(buf, "long"), 0);
}

static void test_internal_xml()
{
	printf("- test xml parser\n");

	xml_attr_t* attr;
	xml_tag_t* root, *h1, *br, *p;
	
	LD_ASSERT(xml_parse(NULL, 0) == NULL);
	LD_ASSERT(xml_parse("foo", 0) == NULL);
	LD_ASSERT(xml_parse(NULL, 255) == NULL);

	const char* src = "<h1>Header Text</h1>";
	root = xml_parse(src, strlen(src));
	CHECK(root);
	h1 = root->child;
	CHECK(strncmp("h1", h1->name.pos, h1->name.len) == 0);
	CHECK(strncmp("Header Text", h1->text.pos, h1->text.len) == 0);
	xml_free(root);

	src = "<h1 class='foo'></h1>";
	root = xml_parse(src, strlen(src));
	CHECK(root);
	h1 = root->child;
	CHECK(h1);
	CHECK(strncmp("h1", h1->name.pos, h1->name.len) == 0);
	attr = h1->attr;
	CHECK(attr);
	CHECK(strncmp("class", attr->name.pos, attr->name.len) == 0);
	CHECK(strncmp("foo", attr->value.pos, attr->value.len) == 0);
	CHECK(attr->next == NULL);
	xml_free(root);


	src = "<br class='c1' id='linebreak' />";
	root = xml_parse(src, strlen(src));
	CHECK(root);
	br = root->child;
	CHECK(br && br->name.pos && !br->text.pos);
	CHECK(br->name.len == 2);
	CHECK(strncmp(br->name.pos, "br", 2) == 0);
	attr = br->attr;
	CHECK(attr);
	CHECK(strncmp("class", attr->name.pos, attr->name.len) == 0);
	CHECK(strncmp("c1", attr->value.pos, attr->value.len) == 0);
	attr = attr->next;
	CHECK(attr);
	CHECK(strncmp("id", attr->name.pos, attr->name.len) == 0);
	CHECK(strncmp("linebreak", attr->value.pos, attr->value.len) == 0);
	xml_free(root);


	src = "<h1><p>subtag content</p></h1>";
	root = xml_parse(src, strlen(src));
	CHECK(root);
	h1 = root->child;
	CHECK(h1);
	CHECK(strncmp("h1", h1->name.pos, h1->name.len) == 0);
	p = h1->child;
	CHECK(p);
	CHECK(strncmp("p", p->name.pos, p->name.len) == 0);
	CHECK(strncmp("subtag content", p->text.pos, p->text.len) == 0);
	xml_free(root);


	src = "<h1><p>content1</p><p>content2</p></h1>";
	root = xml_parse(src, strlen(src));
	CHECK(root);
	h1 = root->child;
	CHECK(strncmp(h1->name.pos, "h1", 2) == 0);
	p = h1->child;
	CHECK(strncmp(p->name.pos, "p", 1) == 0);
	CHECK(strncmp(p->text.pos, "content1", 8) == 0);
	p = p->next;
	CHECK(p && p->next == NULL);
	CHECK(strncmp(p->name.pos, "p", 1) == 0);
	CHECK(strncmp(p->text.pos, "content2", 8) == 0);
	xml_free(root);


	src = "<h1><p>content1</p><br /></h1>";
	root = xml_parse(src, strlen(src));
	CHECK(root);
	h1 = root->child;
	CHECK(h1);
	CHECK(strncmp(h1->name.pos, "h1", 2) == 0);
	p = h1->child;
	CHECK(p);
	CHECK(strncmp(p->name.pos, "p", 1) == 0);
	CHECK(strncmp(p->text.pos, "content1", 8) == 0);
	br = p->next;
	CHECK(br);
	CHECK(strncmp(br->name.pos, "br", 2) == 0);
	xml_free(root);


	xml_tag_t* sys, *provider, * eventid, * version, * level, * task, * opcode, * keywords, * timecreated;
	xml_tag_t* eventrecordid, * correlation, * execution, * channel, * computer, * security;
	xml_tag_t* eventdata, * data;
	src = "<System>"
		    "<Provider Name='Microsoft-Windows-Security-SPP' Guid='{E23B33B0-C8C9-472C-A5F9-F2BDFEA0F156}' EventSourceName='Software Protection Platform Service'/>"
		    "<EventID Qualifiers='16384'>16384</EventID><Version>0</Version><Level>4</Level>"
		    "<Task>0</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2023-07-19T03:01:05.9524657Z'/>"
		    "<EventRecordID>6162</EventRecordID><Correlation/><Execution ProcessID='0' ThreadID='0'/>"
		    "<Channel>Application</Channel><Computer>P23157-NB-CSTI.iii.org.tw</Computer><Security/>"
		  "</System>"
		  "<EventData>"
		    "<Data>2123-06-25T03:01:05Z</Data>"
		    "<Data>RulesEngine</Data>"
		  "</EventData>";
	root = xml_parse(src, strlen(src));
	CHECK(root);
	sys = root->child;
	{
		CHECK(sys && sys->name.pos);
		CHECK(strncmp("System", sys->name.pos, sys->name.len) == 0);
		provider = sys->child;
		CHECK(provider)
		CHECK(strncmp("Provider", provider->name.pos, provider->name.len) == 0);
		{
			attr = provider->attr;
			CHECK(strncmp("Name", attr->name.pos, attr->name.len) == 0);
			CHECK(strncmp("Microsoft-Windows-Security-SPP", attr->value.pos, attr->value.len) == 0);
			attr = attr->next;
			CHECK(strncmp("Guid", attr->name.pos, attr->name.len) == 0);
			CHECK(strncmp("{E23B33B0-C8C9-472C-A5F9-F2BDFEA0F156}", attr->value.pos, attr->value.len) == 0);
			attr = attr->next;
			CHECK(strncmp("EventSourceName", attr->name.pos, attr->name.len) == 0);
			CHECK(strncmp("Software Protection Platform Service", attr->value.pos, attr->value.len) == 0);
			CHECK(attr->next == NULL);
		}
		eventid = provider->next;
		CHECK(eventid);
		CHECK(strncmp("EventID", eventid->name.pos, eventid->name.len) == 0);
		CHECK(strncmp("16384", eventid->text.pos, eventid->text.len) == 0);
		{
			attr = eventid->attr;
			CHECK(strncmp("Qualifiers", attr->name.pos, attr->name.len) == 0);
			CHECK(strncmp("16384", attr->value.pos, attr->value.len) == 0);
			CHECK(attr->next == NULL);
		}
		version = eventid->next;
		CHECK(version);
		CHECK(strncmp("Version", version->name.pos, version->name.len) == 0);
		CHECK(strncmp("0", version->text.pos, version->text.len) == 0);
		level = version->next;
		CHECK(level);
		CHECK(strncmp("Level", level->name.pos, level->name.len) == 0);
		CHECK(strncmp("4", level->text.pos, level->text.len) == 0);
		task = level->next;
		CHECK(task);
		CHECK(strncmp("Task", task->name.pos, task->name.len) == 0);
		CHECK(strncmp("0", task->text.pos, task->text.len) == 0);
		opcode = task->next;
		CHECK(opcode);
		CHECK(strncmp("Opcode", opcode->name.pos, opcode->name.len) == 0);
		CHECK(strncmp("0", opcode->text.pos, opcode->text.len) == 0);
		keywords = opcode->next;
		CHECK(keywords)
		CHECK(strncmp("Keywords", keywords->name.pos, keywords->name.len) == 0);
		CHECK(strncmp("0x80000000000000", keywords->text.pos, keywords->text.len) == 0);
		timecreated = keywords->next;
		CHECK(strncmp("TimeCreated", timecreated->name.pos, timecreated->name.len) == 0);
		{
			attr = timecreated->attr;
			CHECK(strncmp("SystemTime", attr->name.pos, attr->name.len) == 0);
			CHECK(strncmp("2023-07-19T03:01:05.9524657Z", attr->value.pos, attr->value.len) == 0);
			CHECK(attr->next == NULL);
		}
		eventrecordid = timecreated->next;
		CHECK(eventrecordid)
		CHECK(strncmp("EventRecordID", eventrecordid->name.pos, eventrecordid->name.len) == 0);
		CHECK(strncmp("6162", eventrecordid->text.pos, eventrecordid->text.len) == 0);
		correlation = eventrecordid->next;
		CHECK(correlation)
		CHECK(strncmp("Correlation", correlation->name.pos, correlation->name.len) == 0);
		execution = correlation->next;
		CHECK(execution);
		{
			attr = execution->attr;
			CHECK(strncmp("ProcessID", attr->name.pos, attr->name.len) == 0);
			CHECK(strncmp("0", attr->value.pos, attr->value.len) == 0);
			attr = attr->next;
			CHECK(strncmp("ThreadID", attr->name.pos, attr->name.len) == 0);
			CHECK(strncmp("0", attr->value.pos, attr->value.len) == 0);
		}
		channel = execution->next;
		CHECK(channel);
		CHECK(strncmp("Channel", channel->name.pos, channel->name.len) == 0);
		CHECK(strncmp("Application", channel->text.pos, channel->text.len) == 0);
		computer = channel->next;
		CHECK(computer);
		CHECK(strncmp("Computer", computer->name.pos, computer->name.len) == 0);
		CHECK(strncmp("P23157-NB-CSTI.iii.org.tw", computer->text.pos, computer->text.len) == 0);
		security = computer->next;
		CHECK(security);
	}
	eventdata = sys->next;
	CHECK(eventdata);
	CHECK(strncmp("EventData", eventdata->name.pos, eventdata->name.len) == 0);
	{
		data = eventdata->child;
		CHECK(data);
		CHECK(strncmp("Data", data->name.pos, data->name.len) == 0);
		CHECK(strncmp("2123-06-25T03:01:05Z", data->text.pos, data->text.len) == 0);
		data = data->next;
		CHECK(data);
		CHECK(strncmp("Data", data->name.pos, data->name.len) == 0);
		CHECK(strncmp("RulesEngine", data->text.pos, data->text.len) == 0);
		CHECK(data->next == NULL);
	}
	xml_free(root);
}

static void test_internal_syslog()
{
	printf("- test syslog\n");

	// TODO: test get_syslog_ietf_header
}

static void test_internal_multilog()
{
	printf("- test multilog\n");

	int res;
	ld_multilog_t *log;

	const char* s = "@40000000463246022a2ee16d";
	log = new_multilog();
	res = get_multilog_timestamp(&s, log);
	CHECK_INT(res, 1);
	CHECK_INT(*s == '\0', 1);
	CHECK_STR(log->timestamp, "@40000000463246022a2ee16d");
	free_multilog(log);

	s = "@40000004444246022d2ff16d is a valid timestamp";
	log = new_multilog();
	res = get_multilog_timestamp(&s, log);
	CHECK_INT(res, 1);
	CHECK_INT(*s == ' ', 1);
	CHECK_STR(log->timestamp, "@40000004444246022d2ff16d");
	free_multilog(log);

	log = new_multilog();

	s = "@40000004444246022d2ff16dNO WHITESPACE BETWEEN TIMESTAMP AND MSG";
	res = get_multilog_timestamp(&s, log);
	CHECK_INT(res, 0);
	CHECK_INT(*s == '@', 1);
	CHECK_NULL(log->timestamp);

	s = "40000004444246022d2ff1";
	res = get_multilog_timestamp(&s, log);
	CHECK_INT(res, 0);
	CHECK_INT(*s == '4', 1);
	CHECK_NULL(log->timestamp);

	s = "@40000d2ff1";
	res = get_multilog_timestamp(&s, log);
	CHECK_INT(res, 0);
	CHECK_INT(*s == '@', 1);
	CHECK_NULL(log->timestamp);

	free_multilog(log);
}

#ifdef LD_PLATFORM_WINDOWS

static void test_internal_windows()
{
	printf("- test windows platform\n");

	size_t dir_path_len;
	
	dir_path_len = win_get_dir_path("D:\\Logs\\foo.log");
	CHECK_INT(dir_path_len, 7);

	dir_path_len = win_get_dir_path("D:\\Folder\\sys.log");
	CHECK_INT(dir_path_len, 9);
}

#endif // LD_PLATFORM_WINDOWS

void test_internal()
{
	printf("testing internal api\n");
	
	test_internal_string_ops();
	test_internal_xml();
	test_internal_syslog();
	test_internal_multilog();
#ifdef LD_PLATFORM_WINDOWS
	test_internal_windows();
#endif
}

#endif // LD_TEST_INTERNAL
#pragma endregion

#ifdef __cplusplus
}
#endif
