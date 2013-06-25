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

	if(!params[3])
	{
		logprintf("\nMD6 warning: NULL string size passed to native 'md6'\n");

		return NULL;
	}

	amx_GetAddr(amx, params[1], &addr);
	amx_StrParam(amx, params[2], buffer);
	int length = (params[3] + 1);

	if(buffer == NULL)
	{
		logprintf("\nMD6 warning: NULL source string passed to native 'md6'\n");

		return NULL;
	}

	result = (unsigned char *)malloc(length);

	md6_hash(512, (unsigned char *)buffer, strlen(buffer), result);

	dest = (char *)malloc(length);

	binary_hex_represintation(result, dest, ((length - 1) / 2));
	free(result);

	amx_SetString(addr, dest, NULL, NULL, length);

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

	if(!params[3])
	{
		logprintf("\nMD6 warning: NULL string size passed to native 'md6_file'\n");

		return NULL;
	}

	amx_GetAddr(amx, params[1], &addr);
	amx_StrParam(amx, params[2], file);
	int length = (params[3] + 1);

	if(file == NULL)
	{
		logprintf("\nMD6 warning: NULL file passed to native 'md6_file'\n");

		return NULL;
	}

	std::ifstream io(file, std::fstream::binary);

	if(!io.good())
	{
		logprintf("\nMD6 warning: Error while opening file %s for hashing\n", file);

		return NULL;
	}

	result = (unsigned char *)malloc(length);

	io.seekg(NULL, io.end);
	int filesize = io.tellg();
	io.seekg(NULL, io.beg);

	dest = (char *)malloc(filesize);
	io.read(dest, filesize);
	io.close();

	md6_hash(512, (unsigned char *)dest, filesize, result);

	free(dest);
	dest = (char *)malloc(length);

	binary_hex_represintation(result, dest, ((length - 1) / 2));
	free(result);

	amx_SetString(addr, dest, NULL, NULL, length);

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

	if(!params[4])
	{
		logprintf("\nMD6 warning: NULL string size passed to native 'md6_hmac'\n");

		return NULL;
	}

	amx_GetAddr(amx, params[1], &addr);
	amx_StrParam(amx, params[2], buffer);
	amx_StrParam(amx, params[3], hmac);
	int length = (params[4] + 1);

	if(buffer == NULL)
	{
		logprintf("\nMD6 warning: NULL source string passed to native 'md6_hmac'\n");

		return NULL;
	}

	if(hmac == NULL)
	{
		logprintf("\nMD6 warning: NULL HMAC passed to native 'md6_hmac'\n");

		return NULL;
	}

	result = (unsigned char *)malloc(length);

	md6_full_hash(512, (unsigned char *)buffer, strlen(buffer), (unsigned char *)hmac, strlen(hmac), md6_default_L, md6_default_r(512, NULL), result);
	
	dest = (char *)malloc(length);

	binary_hex_represintation(result, dest, ((length - 1) / 2));
	free(result);

	amx_SetString(addr, dest, NULL, NULL, length);

	length = strlen(dest);
	free(dest);

	return length;
}