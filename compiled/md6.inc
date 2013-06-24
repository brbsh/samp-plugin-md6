/*

			     MD6 include
			    BJIADOKC & Co.
	Remove this copyright, if you want to be a superman!
*/





#if defined _md6_included
	#endinput
#endif

#define _md6_included





#pragma tabsize 8




native md6(dest[], source[], size = sizeof dest);
native md6_file(dest[], file[], size = sizeof dest);
native md6_hmac(dest[], source[], key[], ssize = sizeof source, ksize = sizeof key);




#pragma tabsize 4
