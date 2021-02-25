SUBDIR:=log

tmp_objs:=stats.o	\
	allocator.o

build_obj:=$(addprefix $(BASEDIR)/build/$(SUBDIR)/, $(tmp_objs))
objs:=$(objs) $(build_obj)

