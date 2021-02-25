#ifdef __linux__
#include "hosal/linux/file.h"
#elif defined WIN32
#include "hosal/windows/file.h"
#elif defined __APPLE__
#include "hosal/osx/file.h"
#else
#error "Non-supported OS model"
#endif
