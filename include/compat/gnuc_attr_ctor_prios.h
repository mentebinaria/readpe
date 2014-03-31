#pragma once

#if defined(__GNUC__)

#define ATTR_CTOR_PRIO_BASE		1000
#define ATTR_CTOR_PRIO_PLUGINS	ATTR_CTOR_PRIO_BASE + 1
#define ATTR_CTOR_PRIO_OUTPUT	ATTR_CTOR_PRIO_BASE + 2

#endif // if defined(__GNUC__)
