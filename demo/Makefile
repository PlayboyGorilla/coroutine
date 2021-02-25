include os.mk
BASEDIR:=..
BUILDDIR:=$(BASEDIR)/build
CFLAGS:=-Wall -O2 -m64
#CFLAGS:=-g -D__DEBUG__ -Wall -Werror
INCDIR:=-I$(BASEDIR)/
ifeq ($(OS),linux)
LDFLAGS:=-lpthread -ldl -lrt
else
LDFLAGS:=-lpthread -ldl
endif
CC:=gcc

include $(BASEDIR)/build.mk
include $(BASEDIR)/lib/build.mk
include $(BASEDIR)/log/build.mk
include $(BASEDIR)/hosal/$(OS)/build.mk
include $(BASEDIR)/fiber/build.mk

test_fiber:$(objs) test_fiber.o
	$(CC) $(CFLAGS) -o test_fiber $(objs) test_fiber.o $(LDFLAGS)

test_fiber.o:test_fiber.c
	$(CC) $(INCDIR) $(CFLAGS) -c $< -o $@

$(BASEDIR)/log/stats_api.h:$(BASEDIR)/log/stats.h $(BASEDIR)/log/allocator.h
	cd $(BASEDIR)log/;./process_stats.sh

$(objs): $(BUILDDIR)/%.o : $(BASEDIR)/%.c
	$(CC) $(INCDIR) $(CFLAGS) -c $< -o $@

clean:
ifeq ($(OS),linux)
	-rm *.o test_fiber 2>/dev/null
	cd $(BUILDDIR);find -name '*.o'|xargs rm
else
	-rm *.o test_fiber 2>/dev/null
	cd $(BUILDDIR);find ./ -iname '*.o'|xargs rm
endif
