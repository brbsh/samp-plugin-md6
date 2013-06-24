#pragma once



#include <string>
#include <string.h>

#define HAVE_STDINT_H

#include "SDK/plugin.h"
//#include "md6/md6.h"
//#include "md6/md6_nist.h"

#include "natives.h"





typedef void (*logprintf_t)(char *format, ...);



void binary_hex_represintation(unsigned char *binary, char *digest, int length);