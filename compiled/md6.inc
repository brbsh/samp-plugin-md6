/*

					 MD6 include
					BJIADOKC & Co.
	Remove this copyright, if you want to be a superman!
*/





#if defined 			_md6_included
	#endinput
#endif

#define 				_md6_included


#define MD6_MAX_LEN		(128 + 1)





#pragma tabsize 		8




native md6(dest[], source[], size = sizeof dest);
native md6_file(dest[], file[], size = sizeof dest);
native md6_hmac(dest[], source[], key[], size = sizeof dest);





#pragma tabsize 		4
