#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD$

PROG=		xinstall
PROGNAME=	install
SRCS=		xinstall.c getid.c
MAN=		install.1

.PATH:		${.CURDIR}/../../contrib/libmtree
.PATH:		${.CURDIR}/../../lib/libmd
CFLAGS+=	-I${.CURDIR}/../../contrib/libmtree/libmtree
CFLAGS+=	-I${.CURDIR}/../../lib/libnetbsd
CFLAGS+=	-I${.CURDIR}/../../lib/libmd

LIBADD=		md mtree

.include <bsd.prog.mk>
