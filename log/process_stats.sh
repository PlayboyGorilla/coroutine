#!/bin/sh

STATS_H=stats.h
ALLOCATOR_H=allocator.h
STATS_API_H=stats_api.h

echo "static const char *stats_names[] = {" >$STATS_API_H

cat $STATS_H | while read line
do
	name=$(echo -n "$line" | grep -w "^\s*uint32_t" | awk '{print $2}' | cut -d';' -f1)

	if [ "$name" != "" ]; then
		echo "\t\"$name\"," >>$STATS_API_H
	fi
done

echo "};" >>$STATS_API_H

echo "" >>$STATS_API_H
echo "static const char *allocator_names[] = {" >>$STATS_API_H

ALLOC_BEGIN=0
ALLOC_END=0
cat $ALLOCATOR_H | while read line
do
	if [ "$line" = "enum mem_block_index {" ]; then
		ALLOC_BEGIN=1
	elif [ $ALLOC_BEGIN = 1 ]; then
		if [ "$line" = "};" ]; then
			break;
		fi

		name=$(echo -n "$line" | grep -o "MEM_[A-Z_]*")
		if [ "$name" != "" ]; then
			echo "\t\"$name\"," >>$STATS_API_H
		fi
	fi
done
echo "};" >>$STATS_API_H
