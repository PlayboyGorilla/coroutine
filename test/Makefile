include os.mk
BASEDIR:=..
BUILDDIR:=$(BASEDIR)/build
CFLAGS:=-Wall -O2
#CFLAGS:=-g -D__DEBUG__ -Wall -Werror
INCDIR:=-I$(BASEDIR)/
ifeq ($(OS),linux)
LDFLAGS:=-lpthread -ldl -lrt
else
LDFLAGS:=-ldl -lpthread
endif
CC:=gcc

include $(BASEDIR)/build.mk
include $(BASEDIR)/lib/build.mk
include $(BASEDIR)/log/build.mk
include $(BASEDIR)/hosal/$(OS)/build.mk
include $(BASEDIR)/fiber/build.mk

test_dlist:$(objs) test_dlist.o
	$(CC) $(CFLAGS) -o test_dlist $(objs) test_dlist.o $(LDFLAGS)

test_slist:$(objs) test_slist.o
	$(CC) $(CFLAGS) -o test_slist $(objs) test_slist.o $(LDFLAGS)

test_hash:$(objs) test_hash.o
	$(CC) $(CFLAGS) -o test_hash $(objs) test_hash.o $(LDFLAGS)

test_dlist.o:test_dlist.c
	$(CC) $(INCDIR) $(CFLAGS) -c $< -o $@

test_slist.o:test_slist.c
	$(CC) $(INCDIR) $(CFLAGS) -c $< -o $@

test_hash.o:test_hash.c
	$(CC) $(INCDIR) $(CFLAGS) -c $< -o $@

$(BASEDIR)/log/stats_api.h:$(BASEDIR)/log/stats.h $(BASEDIR)/log/allocator.h
	cd $(BASEDIR)log/;./process_stats.sh

$(objs): $(BUILDDIR)/%.o : $(BASEDIR)/%.c
	$(CC) $(INCDIR) $(CFLAGS) -c $< -o $@

all: test_dlist test_slist test_hash

clean:
ifeq ($(OS),linux)
	-rm *.o test_dlist test_slist test_hash 2>/dev/null
	cd $(BUILDDIR);find -name '*.o'|xargs rm
else
	-rm *.o test_dlist test_slist test_hash 2>/dev/null
	cd $(BUILDDIR);find ./ -iname '*.o'|xargs rm
endif
