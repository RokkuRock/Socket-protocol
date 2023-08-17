#ifndef LOG_DIGEST_H
#define LOG_DIGEST_H

#if defined(WIN32)
# define LD_PLATFORM_WINDOWS
#elif defined(__linux__) || defined(UNIX)
# define LD_PLATFORM_UNIX
#else
# error "Unsupported Platform"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define LD_LOG_HEADER  \
	ld_log_type type;  \
	const char *origin;

// unicode codepoint type
typedef uint_least32_t ld_code_t;

typedef enum ld_log_type_ {
	LD_TYPE_SYSLOG = 0,
	LD_TYPE_MULTILOG,
	LD_TYPE_WINEVT_XML,
} ld_log_type;

// the first field of any type of log struct is
// always its corresponding ld_log_type enum
typedef struct ld_log {
	LD_LOG_HEADER
} ld_log_t;


typedef struct ld_syslog ld_syslog_t;
typedef struct ld_multilog ld_multilog_t;
typedef struct ld_winevt_xml ld_winevt_xml_t;


struct ld_syslog {
	LD_LOG_HEADER

	// syslog header fields
	int pri;
	int version;
	char* timestamp; // nullable
	char* hostname;  // nullable
	char* appname;   // nullable
	char* procid;    // nullable
	char* msgid;     // nullable

	// syslog structured-data
	// TODO:

	// application message
	char* msg;
};

struct ld_multilog {
	LD_LOG_HEADER

	// multilog uses TAI64N as its timestamp format
	char* timestamp;

	char* msg;
};

struct ld_winevt_xml {
	LD_LOG_HEADER

	int eventid;
	int version;
	int level;
	int task;
	int opcode;
	int recordid;
};


int ld_init();
void ld_watch_syslog(const char *path);
void ld_watch_multilog(const char *path);
void ld_set_syslog_callback( void(*callback)(ld_syslog_t*) );
void ld_set_multilog_callback( void(*callback)(ld_multilog_t*) );
void ld_poll();
void ld_shutdown();


// Log Parsers API
// they can be called outside of ld_init and ld_shutdown.
// The caller must free the return value manually with ld_free()
ld_syslog_t *ld_parse_syslog(const char *src);
ld_multilog_t *ld_parse_multilog(const char *src);
ld_winevt_xml_t* ld_parse_winevt_xml(const char *src);

void ld_free(ld_log_t *log);


#ifdef __cplusplus
}
#endif

#endif // LOG_DIGEST_H
