#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "lib/errno.h"

static DWORD dw_slot;

int subsys_thread_init(void)
{
	dw_slot = TlsAlloc();
	if (dw_slot == TLS_OUT_OF_INDEXES) {
		return ERR_UNKNOWN;
	}
	return ERR_OK;
}

void subsys_thread_exit(void)
{
	TlsFree(dw_slot);
}

int sys_set_tls(void *data)
{
	BOOL bret;

	bret = TlsSetValue(dw_slot, data);
	if (bret == FALSE) {
		return ERR_UNKNOWN;
	}
	return ERR_OK;
}

void *sys_get_tls(void)
{
	return TlsGetValue(dw_slot);
}

