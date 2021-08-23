# Introduction
This is an open-source implementation of coroutine. The fundamental idea is based on http://dunkels.com/adam/pt/. All codes are written in C.

The project provides a means to write light-weight tasks without creating multiple threads, by letting different tasks runing in the context of one thread. The benefits are
1. reducing overhead incurred by system context switch
2. avoiding error-prone lock coding usually needed in multi-thread programming

The project includes following:

# Features
1. An implementation of fiber and its primitives, including YIELD and SCHEDULE
2. A library of asynchronous socket I/O based on the fiber
3. Timing-wheel-based timers
4. Cross-platform support and unified programming interface for different platforms, currently including Mac OS X and Linux


# Details
1. Each fiber task is tied to a fiber loop(struct fiber_loop object), which essentially is a system thread that runs in a loop. Multiple ftasks can run in the same fiber loop. These tasks are able to access shared data structures and resources without the need for locking.
2. When a task needs to wait for I/O result, sleep for a certain amount of time, or wait for other certain event to happen, it yields by calling FIBER_YIELD() or other variants. The fiber loop then takes over and choose another fiber task, if there's any, to run. The const of context switching (task A yields, fiber loop takes over, task B begins to run) is low. In the demo/test_fiber.c, 100,000 tasks are put on one fiber loop. CPU and memory consumption are both under observable level.
3. Various socket I/O operations are encapsulated as fiber tasks and thus multiple socket I/O operations can be issued on the same fiber loop, and run virtually concurrently. One blocking I/O yields CPU to other runnable tasks and thus the whole process is efficient.
4. On Linux, epoll is used an event monitor for socket I/O. On Mac OSX, it is kqueue. These details and differences are transparent to socket callers.

# Build and Run
[shell] cd demo

Edit os.mk to make 'OS' either osx or linux, depending on the system you are working in.

[shell] make all


# TBD
1. FIBER_SOCKET_XXX() further refactoring needed
2. Support for Windows
