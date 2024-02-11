/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2023 by HAOZHE LI <Arlen-lt@protonmail.com>
   Copyright (C) 2024 by André Guilherme <andregui17@outlook.com>

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

#ifndef SMB2_EXPORT_H
#define SMB2_EXPORT_H

#if defined (_WIN32)
# define SMB2_EXPORT __declspec(dllexport)
#elif defined (__GNUC__)
# define SMB2_EXPORT __attribute__((visibility("default")))
#else
# define SMB2_EXPORT
#endif

#endif /* SMB2_EXPORT_H */
