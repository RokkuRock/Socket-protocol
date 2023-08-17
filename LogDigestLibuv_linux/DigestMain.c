#include <stdio.h>
#include <stdlib.h>
#include "logdigest.h"

void syslog_handler(ld_syslog_t *log)
{
	printf("syslog_handler: new log from %s\n", log->origin);
	printf("- pri %d\n", log->pri);
	printf("- version   %d\n", log->version);
	if (log->timestamp)
		printf("- timestamp %s\n", log->timestamp);
	if (log->hostname)
		printf("- hostname  %s\n", log->hostname);
	if (log->appname)
		printf("- appname %s\n", log->appname);
	if (log->procid)
		printf("- procid %s\n", log->procid);
}

void multilog_handler(ld_multilog_t *log)
{
	printf("multilog_handler: new log from %s\n", log->origin);
	if (log->timestamp)
		printf("- timestamp %s\n", log->timestamp);
	if (log->msg)
		printf("- msg %s\n", log->msg);
}

int main()
{
	ld_init();

	ld_set_syslog_callback(syslog_handler);
	ld_set_multilog_callback(multilog_handler);

	// ld_watch_syslog("/home/yhlee/logdigest/sys01.log");
	// ld_watch_syslog("/home/yhlee/logdigest/sys02.log");
	ld_watch_multilog("/home/vboxuser/Projects/LogUv/multiLogCollector/multi.log");

	// ld_watch_multilog("C:\\Users\\yhlee\\Desktop\\multi.log");
	// ld_watch_syslog("C:\\Users\\yhlee\\Desktop\\sys.log");

	for (;;) {
		ld_poll();
	}

	ld_shutdown();
	return 0;
}
