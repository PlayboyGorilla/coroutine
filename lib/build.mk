SUBDIR:=lib

tmp_objs:=list.o	\
	slist.o		\
	skiplist.o	\
	socketex.o	\
	hash.o		\
	debug.o

build_obj:=$(addprefix $(BASEDIR)/build/$(SUBDIR)/, $(tmp_objs))
objs:=$(objs) $(build_obj)

