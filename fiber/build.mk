SUBDIR:=fiber

tmp_objs:=fiber.o	\
	socket.o

build_obj:=$(addprefix $(BASEDIR)/build/$(SUBDIR)/, $(tmp_objs))
objs:=$(objs) $(build_obj)

