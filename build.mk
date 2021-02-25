SUBDIR:=.

tmp_objs:=init.o

build_obj:=$(addprefix $(BASEDIR)/build/$(SUBDIR)/, $(tmp_objs))
objs:=$(objs) $(build_obj)
