#------------------------------------------------------------------------------
# File: Makefile
#
# Note: This Makefile requires GNU make.
#
# (c) 2001,2000 Stanford University
#
#------------------------------------------------------------------------------

all : sr

CC = gcc

OSTYPE = $(shell uname)

ifeq ($(OSTYPE),CYGWIN_NT-5.1)
ARCH = -D_CYGWIN_
endif

ifeq ($(OSTYPE),Linux)
ARCH = -D_LINUX_
SOCK = -lnsl -lresolv
endif

ifeq ($(OSTYPE),SunOS)
ARCH =  -D_SOLARIS_
SOCK = -lnsl -lsocket -lresolv
endif

ifeq ($(OSTYPE),Darwin)
ARCH = -D_DARWIN_
SOCK = -lresolv
endif

CFLAGS = -g -Wall -std=gnu99 -D_DEBUG_ $(ARCH)

LIBS= $(SOCK) -lm
PFLAGS= -follow-child-processes=yes -cache-dir=/tmp/${USER}
PURIFY= purify ${PFLAGS}

sr_SRCS = sr_router.c sr_main.c  \
          sr_if.c sr_rt.c sr_vns_comm.c   \
          sr_dumper.c sha1.c

sr_OBJS = $(patsubst %.c,%.o,$(sr_SRCS))
sr_DEPS = $(patsubst %.c,.%.d,$(sr_SRCS))

$(sr_OBJS) : %.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(sr_DEPS) : .%.d : %.c
	$(CC) -MM $(CFLAGS) $<  > $@

include $(sr_DEPS)	

sr : $(sr_OBJS)
	$(CC) $(CFLAGS) -o sr $(sr_OBJS) $(LIBS)

sr.purify : $(sr_OBJS)
	$(PURIFY) $(CC) $(CFLAGS) -o sr.purify $(sr_OBJS) $(LIBS)

.PHONY : clean clean-deps dist

clean:
	rm -f *.o *~ core sr *.dump *.tar tags

clean-deps:
	rm -f .*.d

dist-clean: clean clean-deps
	rm -f .*.swp sr_stub.tar.gz

dist: dist-clean
	(cd ..; tar -X stub/exclude -cvf sr_stub.tar stub/; gzip sr_stub.tar); \
    mv ../sr_stub.tar.gz .

tags:
	ctags *.c
