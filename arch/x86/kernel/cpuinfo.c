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
#include <linux/cpuinfo.h>
#include <linux/cpufreq.h>
#include <linux/smp.h>

static ssize_t cpuinfo_stepping(unsigned int c, char *buf)
{
	if (cpu_data(c).x86_mask || cpu_data(c).cpuid_level >= 0)
		return sprintf(buf, "%d\n", cpu_data(c).x86_mask);
	return sprintf(buf, "unknown\n");
}

static ssize_t cpuinfo_flags(unsigned int c, char *buf)
{
	struct cpuinfo_x86 *cpu = &cpu_data(c);
	unsigned int i;
	ssize_t len = 0;

	for (i = 0; i < (32 * NCAPINTS); i++) {
		if (cpu_has(cpu, i) && x86_cap_flags[i] != NULL)
			len += sprintf(buf+len, len == 0 ? "%s" : ",%s",
				       x86_cap_flags[i]);
	}
	if (!len)
		return 0;
	return len + sprintf(buf+len, "\n");
}

static ssize_t cpuinfo_bugs(unsigned int c, char *buf)
{
	struct cpuinfo_x86 *cpu = &cpu_data(c);
	unsigned int i;
	ssize_t len = 0;

	for (i = 0; i < 32*NBUGINTS; i++) {
		unsigned int bug_bit = 32*NCAPINTS + i;

		if (cpu_has_bug(cpu, bug_bit) && x86_bug_flags[i])
			len += sprintf(buf+len, len == 0 ? "%s" : ",%s",
				       x86_bug_flags[i]);
	}
	if (!len)
		return 0;
	return len + sprintf(buf+len, "\n");
}

static ssize_t cpuinfo_bogomips(unsigned int c, char *buf)
{
	struct cpuinfo_x86 cpu = cpu_data(c);

	return sprintf(buf, "%lu.%02lu\n", cpu.loops_per_jiffy / (500000 / HZ),
		       (cpu.loops_per_jiffy / (5000 / HZ)) % 100);
}

#define cpuinfo_cpu_family(cpu)		cpu_data(cpu).x86
#define cpuinfo_model(cpu)		cpu_data(cpu).x86_model

#define cpuinfo_vendor_id(cpu)		cpu_data(cpu).x86_vendor_id[0] ?\
	cpu_data(cpu).x86_vendor_id : "unknown"

#define cpuinfo_model_name(cpu)		cpu_data(cpu).x86_model_id[0] ? \
	cpu_data(cpu).x86_model_id : "unknown"

CPUINFO_DEFINE_ATTR(cpu_family, "%d");
CPUINFO_DEFINE_ATTR(model, "%u");
CPUINFO_DEFINE_ATTR(vendor_id, "%s");
CPUINFO_DEFINE_ATTR(model_name, "%s");

CPUINFO_DEFINE_ATTR_FUNC(stepping);
CPUINFO_DEFINE_ATTR_FUNC(flags);
CPUINFO_DEFINE_ATTR_FUNC(bugs);
CPUINFO_DEFINE_ATTR_FUNC(bogomips);

struct attribute *cpuinfo_attrs[] = {
	CPUINFO_ATTR(vendor_id),
	CPUINFO_ATTR(cpu_family),
	CPUINFO_ATTR(model),
	CPUINFO_ATTR(model_name),
	CPUINFO_ATTR(stepping),
	CPUINFO_ATTR(flags),
	CPUINFO_ATTR(bugs),
	CPUINFO_ATTR(bogomips),
	NULL
};
