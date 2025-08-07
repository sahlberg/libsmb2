/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
#ifndef _USMB2_H_
#define _USMB2_H_

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

/* The largest buffer we need is for SMB2_CREATE as this PDU contains the full name
 * of the file being opened in UCS2, 2 bytes per character.
 *   4 bytes SPL
 *  64 bytes SMB2 header
 *  56 bytes CREATE request header
 * ... and the remaining bytes for the filename being opened.
 */
#define USMB2_SIZE 512

struct usmb2_context {
        int fd;
        uint64_t message_id;
        uint64_t session_id;
        uint32_t tree_id;
        uint8_t buf[USMB2_SIZE];
};

struct usmb2_context *usmb2_init_context(uint32_t ip);

/* Connect to a share. The unc must be of the form \\ip-address\share-name
 * On success it will fill in tree id in the usmb2 context.
 */
int usmb2_treeconnect(struct usmb2_context *usmb2, const char *unc);

/* Open a file. Unicode is out of scope for a tiny-smb2 clients so the filenames you use better
 * be clean 7-bit ASCII.
 * TODO: currently only support O_RDONLY.  Need to add O_RDWR support.
 *
 * There is no close command. Just stop using the file handle and let the server deal with
 * orhpaned open files. It is not like on the type of devices we are targeting will be able to
 * open very many files so that it becomes an issue anyway.
 */
uint8_t *usmb2_open(struct usmb2_context *usmb2, const char *name, int mode);

int usmb2_pread(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, int offset);
int usmb2_pwrite(struct usmb2_context *usmb2, uint8_t *fid, uint8_t *buf, int count, int offset);
int usmb2_size(struct usmb2_context *usmb2, uint8_t *fid);
        
#endif /* !_USMB2_H_ */
