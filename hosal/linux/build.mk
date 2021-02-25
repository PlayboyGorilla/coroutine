SUBDIR:=hosal/linux

tmp_objs:=timer.o		\
	thread.o		\
	socket.o		\
	fiber.o

build_obj:=$(addprefix $(BASEDIR)/build/$(SUBDIR)/, $(tmp_objs))

objs:=$(objs) $(build_obj)
