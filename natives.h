#pragma once



#include "md6.h"





class amxNatives
{

public:

	static const AMX_NATIVE_INFO md6Natives[];

	static cell AMX_NATIVE_CALL MD6(AMX *amx, cell *params);
};