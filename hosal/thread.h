#ifdef __linux__
#include "hosal/linux/thread.h"
#elif defined WIN32
#include "hosal/windows/thread.h"
#elif defined __APPLE__
#include "hosal/osx/thread.h"
#else
#error "Non-supported OS model"
#endif
