#ifdef __linux__
#include "hosal/linux/type.h"
#elif defined WIN32
#include "hosal/win/type.h"
#elif defined __APPLE__
#include "hosal/osx/type.h"
#else
#error "Non-supported OS model"
#endif
