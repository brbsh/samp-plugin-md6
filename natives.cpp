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
	{"md6_file", amxNatives::MD6_file},
	{"md6_hmac", amxNatives::MD6_hmac},

	{NULL, NULL}
};



// native md6(dest[], source[], size = sizeof dest);
cell AMX_NATIVE_CALL amxNatives::MD6(AMX *amx, cell *params)
{
	char *buffer = NULL;
	char *dest = NULL;
	unsigned char *result = NULL;
	cell *addr = NULL;

	amx_GetAddr(amx, params[1], &addr);
	amx_StrParam(amx, params[2], buffer);
	int length = params[3];

	result = (unsigned char *)malloc(++length);

	md6_hash((32 * 8), (unsigned char *)buffer, strlen(buffer), result);

	dest = (char *)malloc(length);

	binary_hex_represintation(result, dest, (--length / 2));
	free(result);
	amx_SetString(addr, dest, NULL, NULL, ++length);

	length = strlen(dest);
	free(dest);

	return length;
}



cell AMX_NATIVE_CALL amxNatives::MD6_file(AMX *amx, cell *params)
{
	char *file = NULL;
	char *dest = NULL;
	unsigned char *result = NULL;
	cell *addr = NULL;

	amx_GetAddr(amx, params[1], &addr);
	amx_StrParam(amx, params[2], file);
	int amx_length = params[3];

	result = (unsigned char *)malloc(++amx_length);

	std::ifstream io(file, std::fstream::binary);

	io.seekg(NULL, io.end);
	int length = io.tellg();
	io.seekg(NULL, io.beg);

	dest = (char *)malloc(length);
	io.read(dest, length);
	io.close();

	amx_length--;
	md6_hash((32 * 8), (unsigned char *)dest, length, result);

	free(dest);
	dest = (char *)malloc(++amx_length);

	binary_hex_represintation(result, dest, (--amx_length / 2));
	free(result);
	amx_SetString(addr, dest, NULL, NULL, ++amx_length);

	length = strlen(dest);
	free(dest);

	return length;
}



cell AMX_NATIVE_CALL amxNatives::MD6_hmac(AMX *amx, cell *params)
{
	char *buffer = NULL;
	char *dest = NULL;
	char *hmac = NULL;
	unsigned char *result = NULL;
	cell *addr = NULL;

	amx_GetAddr(amx, params[1], &addr);
	amx_StrParam(amx, params[2], buffer);
	amx_StrParam(amx, params[3], hmac);
	int length = params[4];

	result = (unsigned char *)malloc(++length);

	md6_full_hash((32 * 8), (unsigned char *)buffer, strlen(buffer), (unsigned char *)hmac, strlen(hmac), md6_default_L, md6_default_r((32 * 8), NULL), result);
	
	dest = (char *)malloc(length);

	binary_hex_represintation(result, dest, (--length / 2));
	free(result);
	amx_SetString(addr, dest, NULL, NULL, ++length);

	length = strlen(dest);
	free(dest);

	return length;
}