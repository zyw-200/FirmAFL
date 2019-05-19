/* For CCAN */

#include <endian.h>
#include <byteswap.h>

#define HAVE_TYPEOF			1
#define HAVE_BUILTIN_TYPES_COMPATIBLE_P	1


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define HAVE_BIG_ENDIAN         0
#define HAVE_LITTLE_ENDIAN      1
#else
#define HAVE_BIG_ENDIAN         1
#define HAVE_LITTLE_ENDIAN      0
#endif

#define HAVE_BYTESWAP_H 1
#define HAVE_BSWAP_64	1
