#pragma once



#include <fstream>
#include <string>
#include <string.h>

#define HAVE_STDINT_H

#include "SDK/plugin.h"

#include "natives.h"





#define arguments(n) \
	(params[0] == (n << 2))





typedef void (*logprintf_t)(char *format, ...);



void binary_hex_represintation(unsigned char *binary, char *digest, int length);