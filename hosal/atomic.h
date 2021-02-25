#ifdef __linux__
#include "hosal/linux/atomic.h"
#elif defined WIN32
#include "hosal/windows/atomic.h"
#elif defined __APPLE__
#include "hosal/osx/atomic.h"
#else
#error "Non-supported OS model"
#endif
