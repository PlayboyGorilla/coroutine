SUBDIR:=hosal/osx

tmp_objs:=timer.o		\
	socket.o		\
	thread.o		\
	fiber.o			\
	type.o

build_obj:=$(addprefix $(BASEDIR)/build/$(SUBDIR)/, $(tmp_objs))

objs:=$(objs) $(build_obj)
