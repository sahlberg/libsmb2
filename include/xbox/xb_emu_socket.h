#ifndef _EMU_SOCKET_H
#define _EMU_SOCKET_H

/*
 *      Copyright (C) 2005-2013 Team XBMC
 *      http://xbmc.org
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 */

#include "emu_socket.h"
#include "addrinfo.h"
#include "bittypes.h"
#include "sockstorage.h"

// OS support start
typedef int socklen_t;

#define POLLIN      0x0001    /* There is data to read */
#define POLLPRI     0x0002    /* There is urgent data to read */
#define POLLOUT     0x0004    /* Writing now will not block */
#define POLLERR     0x0008    /* Error condition */
#define POLLHUP     0x0010    /* Hung up */

#ifndef XBOX_PLATFORM
#define ssize_t __int64 /* MSVC 2003 yells about this one. */
#endif
// OS support end

#ifdef __cplusplus
extern "C"
{
#endif

  struct mphostent* __stdcall sckemu_gethostbyname(const char* name);
//char* __stdcall inet_ntoa(in_addr in);
  int __stdcall sckemu_connect(int s, const struct sockaddr FAR *name, int namelen);
  int __stdcall sckemu_send(int s, const char FAR *buf, int len, int flags);
  int __stdcall sckemu_socket(int af, int type, int protocol);
  int __stdcall sckemu_bind(int s, const struct sockaddr FAR * name, int namelen);
  int __stdcall sckemu_closesocket(int s);
  int __stdcall sckemu_getsockopt(int s, int level, int optname, char FAR * optval, int FAR * optlen);
  int __stdcall sckemu_ioctlsocket(int s, long cmd, DWORD FAR * argp);
  int __stdcall sckemu_recv(int s, char FAR * buf, int len, int flags);
  int __stdcall sckemu_select(int nfds, fd_set FAR * readfds, fd_set FAR * writefds, fd_set FAR *exceptfds, const struct timeval FAR * timeout);
  int __stdcall sckemu_sendto(int s, const char FAR * buf, int len, int flags, const struct sockaddr FAR * to, int tolen);
  int __stdcall sckemu_setsockopt(int s, int level, int optname, const char FAR * optval, int optlen);
  int __stdcall sckemu_WSAFDIsSet(int fd, fd_set* set);

  int __stdcall sckemu_accept(int s, struct sockaddr FAR * addr, OUT int FAR * addrlen);
  int __stdcall sckemu_gethostname(char* name, int namelen);
  int __stdcall sckemu_getsockname(int s, struct sockaddr* name, int* namelen);
  int __stdcall sckemu_listen(int s, int backlog);
  u_short __stdcall sckemu_ntohs(u_short netshort);
  int __stdcall sckemu_recvfrom(int s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
  int __stdcall sckemu_shutdown(int s, int how);
  char* __stdcall sckemu_ntoa(struct in_addr in);

  struct servent* __stdcall sckemu_getservbyname(const char* name,const char* proto);
  struct protoent* __stdcall sckemu_getprotobyname(const char* name);
  int __stdcall sckemu_getpeername(int s, struct sockaddr FAR *name, int FAR *namelen);
  struct servent* __stdcall sckemu_getservbyport(int port, const char* proto);
  struct mphostent* __stdcall sckemu_gethostbyaddr(const char* addr, int len, int type);

  int __stdcall sckemu_getaddrinfo(const char* nodename, const char* servname, const struct addrinfo* hints, struct addrinfo** res);
  int __stdcall sckemu_getnameinfo(const struct sockaddr *sa, size_t salen, char *host, size_t hostlen, char *serv, size_t servlen, int flags);
  void __stdcall sckemu_freeaddrinfo(struct addrinfo *ai);
  
#ifdef __cplusplus
}
#endif

#endif // _EMU_SOCKET_H