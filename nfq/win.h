#pragma once

#ifdef __CYGWIN__

#include <stdbool.h>

bool service_run();
void service_stopped();

#endif

