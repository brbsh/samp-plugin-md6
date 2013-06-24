#pragma once
#pragma warning(disable:4244)



#include "md6/md6.h"
#include "md6/md6_compress.c"
#include "md6/md6_mode.c"
#include "natives.h"





extern logprintf_t logprintf;





const AMX_NATIVE_INFO amxNatives::md6Natives[] = 
{
	{"md6", amxNatives::MD6},

	{NULL, NULL}
};



// native md6(dest[], source[], size = sizeof dest);
cell AMX_NATIVE_CALL amxNatives::MD6(AMX *amx, cell *params)
{
	char *buffer = NULL;
	unsigned char *result = NULL;
	cell *addr = NULL;

	amx_StrParam(amx, params[2], buffer);

	int length = strlen(buffer);
	int amx_length = (params[3] + 1);

	buffer = (char *)malloc(amx_length);
	result = (unsigned char *)malloc(amx_length);

	md6_hash((--amx_length * 8), (unsigned char *)buffer, length, result);

	binary_hex_represintation(result, buffer, (amx_length / 2));
	free(result);

	logprintf("Output: %s %i", buffer, amx_length);

	amx_GetAddr(amx, params[1], &addr);
	amx_SetString(addr, buffer, NULL, NULL, ++amx_length);

	length = strlen(buffer);

	free(buffer);

	return length;
}