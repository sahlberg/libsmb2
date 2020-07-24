/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#define _GNU_SOURCE

#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"

int is_finished;
uint8_t buf[256 * 1024];
uint32_t pos;

/*
 * Test version to measure how much footprint that are taken if we only
 * need smb2_read()/smb2_read_async() from libsmb2;
 */
int main(int argc, char *argv[])
{
        struct smb2_context *smb2 = NULL;
	struct pollfd pfd;
        int rc;

        rc = smb2_read(NULL, NULL, NULL, 0);
        printf("rc:%d\n", rc);
        rc = smb2_read_async(NULL, NULL, NULL, 0, NULL, NULL);
        printf("rc:%d\n", rc);
        while (!is_finished) {
		pfd.fd = smb2_get_fd(smb2);
		pfd.events = smb2_which_events(smb2);

		if (poll(&pfd, 1, 1000) < 0) {
			printf("Poll failed");
			exit(10);
		}
                if (pfd.revents == 0) {
                        continue;
                }
		if (smb2_service(smb2, pfd.revents) < 0) {
			printf("smb2_service failed with : %s\n",
                               smb2_get_error(smb2));
			break;
		}
	}

	return 0;
}
