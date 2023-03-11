#ifdef __linux__
#include "hosal/linux/inet.h"
#elif defined WIN32
#include "hosal/win/inet.h"
#elif defined __APPLE__
#include "hosal/osx/inet.h"
#else
#error "Non-supported OS model"
#endif
