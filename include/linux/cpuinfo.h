/*
 * Copyright (C) 2017 SUSE Linux GmbH
 * Written by: Felix Schnizlein <fschnizlein@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */
#ifndef _LINUX_CPUINFO_H
#define _LINUX_CPUINFO_H

#ifdef CONFIG_HAVE_CPUINFO_SYSFS
extern struct attribute *cpuinfo_attrs[];

#define CPUINFO_DEFINE_ATTR(name, format)				\
static ssize_t name##_show(struct device *dev,				\
			   struct device_attribute *attr,		\
			   char *buf)					\
{									\
	return sprintf(buf, format"\n", cpuinfo_##name(dev->id));	\
}									\
static DEVICE_ATTR_RO(name)


#define CPUINFO_DEFINE_ATTR_FUNC(name)					\
static ssize_t name##_show(struct device *dev,				\
			   struct device_attribute *attr,		\
			   char *buf)					\
{									\
	return cpuinfo_##name(dev->id, buf);				\
}									\
static DEVICE_ATTR_RO(name)


#define CPUINFO_ATTR(name)			(&dev_attr_##name.attr)
#endif /* CONFIG_HAVE_CPUINFO_SYSFS */

#endif /* _LINUX_CPUINFO_H */
