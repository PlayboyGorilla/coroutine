#ifdef __linux__
#include "hosal/linux/byteorder.h"
#elif defined WIN32
#include "hosal/win/byteorder.h"
#elif defined __APPLE__
#include "hosal/osx/byteorder.h"
#else
#error "Non-supported OS model"
#endif
