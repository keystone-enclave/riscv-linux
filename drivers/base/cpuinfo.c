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
 *
 */

#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/cpuinfo.h>

static struct attribute_group cpuinfo_attr_group = {
	.attrs = cpuinfo_attrs,
	.name = "info"
};

static int cpuinfo_add_dev(unsigned int cpu)
{
	struct device *dev = get_cpu_device(cpu);

	return sysfs_create_group(&dev->kobj, &cpuinfo_attr_group);
}

static int cpuinfo_remove_dev(unsigned int cpu)
{
	struct device *dev = get_cpu_device(cpu);

	sysfs_remove_group(&dev->kobj, &cpuinfo_attr_group);
	return 0;
}

static int cpuinfo_sysfs_init(void)
{
	return cpuhp_setup_state(CPUHP_CPUINFO_PREPARE,
				 "base/cpuinfo:prepare",
				 cpuinfo_add_dev,
				 cpuinfo_remove_dev);
}

device_initcall(cpuinfo_sysfs_init);
