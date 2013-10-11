#pragma once
#pragma warning(disable:4244)



#ifdef LINUX
	#include <alloca.h>
#endif

#include <fstream>
#include <string>

#define HAVE_STDINT_H

#include "SDK/plugin.h"

#include "natives.h"





#define PLUGIN_VERSION "1.1"

#define arguments(n) \
	(params[0] == (n << 2))





typedef void (*logprintf_t)(char *format, ...);

void binary_hex_represintation(unsigned char *binary, char *digest, int length);