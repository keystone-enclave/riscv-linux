#ifndef _KEYSTONE_H_
#define _KEYSTONE_H_

#include <linux/file.h>

long keystone_ioctl(struct file* filep, unsigned int cmd, unsigned long arg);
#endif
