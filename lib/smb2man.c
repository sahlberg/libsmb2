/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * Initialization code for PS2 IOP platform.
 */
/*
   Copyright (C) 2020 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <intrman.h>
#include <irx.h>
#include <loadcore.h>
#include <sysclib.h>
#include <sysmem.h>
#include <sifman.h>
#include <thevent.h>
#include <thsemap.h>
#include <netman.h>
#include <netman_rpc.h>

#include "compat.h"

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

int _start(int argc, char** argv)
{

        /*
         * Stuff goes here
         */

	return MODULE_RESIDENT_END;
}
void *malloc(size_t size){
	int OldState;
	void *result;

	CpuSuspendIntr(&OldState);
	result = AllocSysMemory(ALLOC_FIRST, size, NULL);
	CpuResumeIntr(OldState);

	return result;
}

void free(void *buffer){
	int OldState;

	CpuSuspendIntr(&OldState);
	FreeSysMemory(buffer);
	CpuResumeIntr(OldState);
}

void *calloc(size_t n, size_t size)
{
        int flags;
        void *ptr;

        CpuSuspendIntr(&flags);
        ptr=AllocSysMemory(ALLOC_LAST, n * size, NULL);
        CpuResumeIntr(flags);

        if(ptr != NULL)
                memset(ptr, 0, n * size);

        return ptr;
}
