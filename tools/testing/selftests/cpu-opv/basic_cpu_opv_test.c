/*
 * Basic test coverage for cpu_opv system call.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <stdlib.h>

#include "cpu-op.h"

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

#define TESTBUFLEN	4096
#define TESTBUFLEN_CMP	16

#define TESTBUFLEN_PAGE_MAX	65536

static int test_compare_eq_op(char *a, char *b, size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.a, a),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.b, b),
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_compare_eq_same(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_compare_eq same";

	printf("Testing %s\n", test_name);

	/* Test compare_eq */
	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	for (i = 0; i < TESTBUFLEN; i++)
		buf2[i] = (char)i;
	ret = test_compare_eq_op(buf2, buf1, TESTBUFLEN);
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret > 0) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 0);
		return -1;
	}
	return 0;
}

static int test_compare_eq_diff(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_compare_eq different";

	printf("Testing %s\n", test_name);

	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN);
	ret = test_compare_eq_op(buf2, buf1, TESTBUFLEN);
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret == 0) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 1);
		return -1;
	}
	return 0;
}

static int test_compare_ne_op(char *a, char *b, size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_NE_OP,
			.len = len,
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.a, a),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.b, b),
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_compare_ne_same(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_compare_ne same";

	printf("Testing %s\n", test_name);

	/* Test compare_ne */
	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	for (i = 0; i < TESTBUFLEN; i++)
		buf2[i] = (char)i;
	ret = test_compare_ne_op(buf2, buf1, TESTBUFLEN);
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret == 0) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 1);
		return -1;
	}
	return 0;
}

static int test_compare_ne_diff(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_compare_ne different";

	printf("Testing %s\n", test_name);

	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN);
	ret = test_compare_ne_op(buf2, buf1, TESTBUFLEN);
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret != 0) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 0);
		return -1;
	}
	return 0;
}

static int test_2compare_eq_op(char *a, char *b, char *c, char *d,
		size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.a, a),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.b, b),
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[1] = {
			.op = CPU_COMPARE_EQ_OP,
			.len = len,
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.a, c),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.b, d),
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_2compare_eq_index(void)
{
	int i, ret;
	char buf1[TESTBUFLEN_CMP];
	char buf2[TESTBUFLEN_CMP];
	char buf3[TESTBUFLEN_CMP];
	char buf4[TESTBUFLEN_CMP];
	const char *test_name = "test_2compare_eq index";

	printf("Testing %s\n", test_name);

	for (i = 0; i < TESTBUFLEN_CMP; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN_CMP);
	memset(buf3, 0, TESTBUFLEN_CMP);
	memset(buf4, 0, TESTBUFLEN_CMP);

	/* First compare failure is op[0], expect 1. */
	ret = test_2compare_eq_op(buf2, buf1, buf4, buf3, TESTBUFLEN_CMP);
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret != 1) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 1);
		return -1;
	}

	/* All compares succeed. */
	for (i = 0; i < TESTBUFLEN_CMP; i++)
		buf2[i] = (char)i;
	ret = test_2compare_eq_op(buf2, buf1, buf4, buf3, TESTBUFLEN_CMP);
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret != 0) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 0);
		return -1;
	}

	/* First compare failure is op[1], expect 2. */
	for (i = 0; i < TESTBUFLEN_CMP; i++)
		buf3[i] = (char)i;
	ret = test_2compare_eq_op(buf2, buf1, buf4, buf3, TESTBUFLEN_CMP);
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret != 2) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 2);
		return -1;
	}

	return 0;
}

static int test_2compare_ne_op(char *a, char *b, char *c, char *d,
		size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_COMPARE_NE_OP,
			.len = len,
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.a, a),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.b, b),
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
		[1] = {
			.op = CPU_COMPARE_NE_OP,
			.len = len,
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.a, c),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.compare_op.b, d),
			.u.compare_op.expect_fault_a = 0,
			.u.compare_op.expect_fault_b = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_2compare_ne_index(void)
{
	int i, ret;
	char buf1[TESTBUFLEN_CMP];
	char buf2[TESTBUFLEN_CMP];
	char buf3[TESTBUFLEN_CMP];
	char buf4[TESTBUFLEN_CMP];
	const char *test_name = "test_2compare_ne index";

	printf("Testing %s\n", test_name);

	memset(buf1, 0, TESTBUFLEN_CMP);
	memset(buf2, 0, TESTBUFLEN_CMP);
	memset(buf3, 0, TESTBUFLEN_CMP);
	memset(buf4, 0, TESTBUFLEN_CMP);

	/* First compare ne failure is op[0], expect 1. */
	ret = test_2compare_ne_op(buf2, buf1, buf4, buf3, TESTBUFLEN_CMP);
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret != 1) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 1);
		return -1;
	}

	/* All compare ne succeed. */
	for (i = 0; i < TESTBUFLEN_CMP; i++)
		buf1[i] = (char)i;
	for (i = 0; i < TESTBUFLEN_CMP; i++)
		buf3[i] = (char)i;
	ret = test_2compare_ne_op(buf2, buf1, buf4, buf3, TESTBUFLEN_CMP);
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret != 0) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 0);
		return -1;
	}

	/* First compare failure is op[1], expect 2. */
	for (i = 0; i < TESTBUFLEN_CMP; i++)
		buf4[i] = (char)i;
	ret = test_2compare_ne_op(buf2, buf1, buf4, buf3, TESTBUFLEN_CMP);
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret != 2) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 2);
		return -1;
	}

	return 0;
}

static int test_memcpy_op(void *dst, void *src, size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.dst, dst),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.src, src),
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_memcpy(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_memcpy";

	printf("Testing %s\n", test_name);

	/* Test memcpy */
	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN);
	ret = test_memcpy_op(buf2, buf1, TESTBUFLEN);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	for (i = 0; i < TESTBUFLEN; i++) {
		if (buf2[i] != (char)i) {
			printf("%s failed. Expecting '%d', found '%d' at offset %d\n",
				test_name, (char)i, buf2[i], i);
			return -1;
		}
	}
	return 0;
}

static int test_memcpy_u32(void)
{
	int ret;
	uint32_t v1, v2;
	const char *test_name = "test_memcpy_u32";

	printf("Testing %s\n", test_name);

	/* Test memcpy_u32 */
	v1 = 42;
	v2 = 0;
	ret = test_memcpy_op(&v2, &v1, sizeof(v1));
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (v1 != v2) {
		printf("%s failed. Expecting '%d', found '%d'\n",
			test_name, v1, v2);
		return -1;
	}
	return 0;
}

static int test_memcpy_mb_memcpy_op(void *dst1, void *src1,
		void *dst2, void *src2, size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.dst, dst1),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.src, src1),
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
		[1] = {
			.op = CPU_MB_OP,
		},
		[2] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.dst, dst2),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.src, src2),
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_memcpy_mb_memcpy(void)
{
	int ret;
	int v1, v2, v3;
	const char *test_name = "test_memcpy_mb_memcpy";

	printf("Testing %s\n", test_name);

	/* Test memcpy */
	v1 = 42;
	v2 = v3 = 0;
	ret = test_memcpy_mb_memcpy_op(&v2, &v1, &v3, &v2, sizeof(int));
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (v3 != v1) {
		printf("%s failed. Expecting '%d', found '%d'\n",
			test_name, v1, v3);
		return -1;
	}
	return 0;
}

static int test_add_op(int *v, int64_t increment)
{
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_op_add(v, increment, sizeof(*v), cpu);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_add(void)
{
	int orig_v = 42, v, ret;
	int increment = 1;
	const char *test_name = "test_add";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_add_op(&v, increment);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		return -1;
	}
	if (v != orig_v + increment) {
		printf("%s unexpected value: %d. Should be %d.\n",
			test_name, v, orig_v);
		return -1;
	}
	return 0;
}

static int test_two_add_op(int *v, int64_t *increments)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_ADD_OP,
			.len = sizeof(*v),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(
				.u.arithmetic_op.p, v),
			.u.arithmetic_op.count = increments[0],
			.u.arithmetic_op.expect_fault_p = 0,
		},
		[1] = {
			.op = CPU_ADD_OP,
			.len = sizeof(*v),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(
				.u.arithmetic_op.p, v),
			.u.arithmetic_op.count = increments[1],
			.u.arithmetic_op.expect_fault_p = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_two_add(void)
{
	int orig_v = 42, v, ret;
	int64_t increments[2] = { 99, 123 };
	const char *test_name = "test_two_add";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_two_add_op(&v, increments);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		return -1;
	}
	if (v != orig_v + increments[0] + increments[1]) {
		printf("%s unexpected value: %d. Should be %d.\n",
			test_name, v, orig_v);
		return -1;
	}
	return 0;
}

static int test_or_op(int *v, uint64_t mask)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_OR_OP,
			.len = sizeof(*v),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(
				.u.bitwise_op.p, v),
			.u.bitwise_op.mask = mask,
			.u.bitwise_op.expect_fault_p = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_or(void)
{
	int orig_v = 0xFF00000, v, ret;
	uint32_t mask = 0xFFF;
	const char *test_name = "test_or";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_or_op(&v, mask);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v | mask)) {
		printf("%s unexpected value: %d. Should be %d.\n",
			test_name, v, orig_v | mask);
		return -1;
	}
	return 0;
}

static int test_and_op(int *v, uint64_t mask)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_AND_OP,
			.len = sizeof(*v),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(
				.u.bitwise_op.p, v),
			.u.bitwise_op.mask = mask,
			.u.bitwise_op.expect_fault_p = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_and(void)
{
	int orig_v = 0xF00, v, ret;
	uint32_t mask = 0xFFF;
	const char *test_name = "test_and";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_and_op(&v, mask);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v & mask)) {
		printf("%s unexpected value: %d. Should be %d.\n",
			test_name, v, orig_v & mask);
		return -1;
	}
	return 0;
}

static int test_xor_op(int *v, uint64_t mask)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_XOR_OP,
			.len = sizeof(*v),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(
				.u.bitwise_op.p, v),
			.u.bitwise_op.mask = mask,
			.u.bitwise_op.expect_fault_p = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_xor(void)
{
	int orig_v = 0xF00, v, ret;
	uint32_t mask = 0xFFF;
	const char *test_name = "test_xor";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_xor_op(&v, mask);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v ^ mask)) {
		printf("%s unexpected value: %d. Should be %d.\n",
			test_name, v, orig_v ^ mask);
		return -1;
	}
	return 0;
}

static int test_lshift_op(int *v, uint32_t bits)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_LSHIFT_OP,
			.len = sizeof(*v),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(
				.u.shift_op.p, v),
			.u.shift_op.bits = bits,
			.u.shift_op.expect_fault_p = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_lshift(void)
{
	int orig_v = 0xF00, v, ret;
	uint32_t bits = 5;
	const char *test_name = "test_lshift";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_lshift_op(&v, bits);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v << bits)) {
		printf("%s unexpected value: %d. Should be %d.\n",
			test_name, v, orig_v << bits);
		return -1;
	}
	return 0;
}

static int test_rshift_op(int *v, uint32_t bits)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_RSHIFT_OP,
			.len = sizeof(*v),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(
				.u.shift_op.p, v),
			.u.shift_op.bits = bits,
			.u.shift_op.expect_fault_p = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_rshift(void)
{
	int orig_v = 0xF00, v, ret;
	uint32_t bits = 5;
	const char *test_name = "test_rshift";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_rshift_op(&v, bits);
	if (ret) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		return -1;
	}
	if (v != (orig_v >> bits)) {
		printf("%s unexpected value: %d. Should be %d.\n",
			test_name, v, orig_v >> bits);
		return -1;
	}
	return 0;
}

static int test_cmpxchg_op(void *v, void *expect, void *old, void *n,
		size_t len)
{
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_op_cmpxchg(v, expect, old, n, len, cpu);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}


static int test_cmpxchg_success(void)
{
	int ret;
	uint64_t orig_v = 1, v, expect = 1, old = 0, n = 3;
	const char *test_name = "test_cmpxchg success";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_cmpxchg_op(&v, &expect, &old, &n, sizeof(uint64_t));
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 0);
		return -1;
	}
	if (v != n) {
		printf("%s v is %lld, expecting %lld\n",
			test_name, (long long)v, (long long)n);
		return -1;
	}
	if (old != orig_v) {
		printf("%s old is %lld, expecting %lld\n",
			test_name, (long long)old, (long long)orig_v);
		return -1;
	}
	return 0;
}

static int test_cmpxchg_fail(void)
{
	int ret;
	uint64_t orig_v = 1, v, expect = 123, old = 0, n = 3;
	const char *test_name = "test_cmpxchg fail";

	printf("Testing %s\n", test_name);

	v = orig_v;
	ret = test_cmpxchg_op(&v, &expect, &old, &n, sizeof(uint64_t));
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	if (ret == 0) {
		printf("%s returned %d, expecting %d\n",
			test_name, ret, 1);
		return -1;
	}
	if (v == n) {
		printf("%s v is %lld, expecting %lld\n",
			test_name, (long long)v, (long long)orig_v);
		return -1;
	}
	if (old != orig_v) {
		printf("%s old is %lld, expecting %lld\n",
			test_name, (long long)old, (long long)orig_v);
		return -1;
	}
	return 0;
}

static int test_memcpy_expect_fault_op(void *dst, void *src, size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.dst, dst),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.src, src),
			.u.memcpy_op.expect_fault_dst = 0,
			/* Return EAGAIN on fault. */
			.u.memcpy_op.expect_fault_src = 1,
		},
	};
	int cpu;

	cpu = cpu_op_get_current_cpu();
	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

static int test_memcpy_fault(void)
{
	int ret;
	char buf1[TESTBUFLEN];
	const char *test_name = "test_memcpy_fault";

	printf("Testing %s\n", test_name);

	/* Test memcpy */
	ret = test_memcpy_op(buf1, NULL, TESTBUFLEN);
	if (!ret || (ret < 0 && errno != EFAULT)) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	/* Test memcpy expect fault */
	ret = test_memcpy_expect_fault_op(buf1, NULL, TESTBUFLEN);
	if (!ret || (ret < 0 && errno != EAGAIN)) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	return 0;
}

static int do_test_unknown_op(void)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = -1,	/* Unknown */
			.len = 0,
		},
	};
	int cpu;

	cpu = cpu_op_get_current_cpu();
	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

static int test_unknown_op(void)
{
	int ret;
	const char *test_name = "test_unknown_op";

	printf("Testing %s\n", test_name);

	ret = do_test_unknown_op();
	if (!ret || (ret < 0 && errno != EINVAL)) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	return 0;
}

static int do_test_max_ops(void)
{
	struct cpu_op opvec[] = {
		[0] = { .op = CPU_MB_OP, },
		[1] = { .op = CPU_MB_OP, },
		[2] = { .op = CPU_MB_OP, },
		[3] = { .op = CPU_MB_OP, },
		[4] = { .op = CPU_MB_OP, },
		[5] = { .op = CPU_MB_OP, },
		[6] = { .op = CPU_MB_OP, },
		[7] = { .op = CPU_MB_OP, },
		[8] = { .op = CPU_MB_OP, },
		[9] = { .op = CPU_MB_OP, },
		[10] = { .op = CPU_MB_OP, },
		[11] = { .op = CPU_MB_OP, },
		[12] = { .op = CPU_MB_OP, },
		[13] = { .op = CPU_MB_OP, },
		[14] = { .op = CPU_MB_OP, },
		[15] = { .op = CPU_MB_OP, },
	};
	int cpu;

	cpu = cpu_op_get_current_cpu();
	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

static int test_max_ops(void)
{
	int ret;
	const char *test_name = "test_max_ops";

	printf("Testing %s\n", test_name);

	ret = do_test_max_ops();
	if (ret < 0) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	return 0;
}

static int do_test_too_many_ops(void)
{
	struct cpu_op opvec[] = {
		[0] = { .op = CPU_MB_OP, },
		[1] = { .op = CPU_MB_OP, },
		[2] = { .op = CPU_MB_OP, },
		[3] = { .op = CPU_MB_OP, },
		[4] = { .op = CPU_MB_OP, },
		[5] = { .op = CPU_MB_OP, },
		[6] = { .op = CPU_MB_OP, },
		[7] = { .op = CPU_MB_OP, },
		[8] = { .op = CPU_MB_OP, },
		[9] = { .op = CPU_MB_OP, },
		[10] = { .op = CPU_MB_OP, },
		[11] = { .op = CPU_MB_OP, },
		[12] = { .op = CPU_MB_OP, },
		[13] = { .op = CPU_MB_OP, },
		[14] = { .op = CPU_MB_OP, },
		[15] = { .op = CPU_MB_OP, },
		[16] = { .op = CPU_MB_OP, },
	};
	int cpu;

	cpu = cpu_op_get_current_cpu();
	return cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
}

static int test_too_many_ops(void)
{
	int ret;
	const char *test_name = "test_too_many_ops";

	printf("Testing %s\n", test_name);

	ret = do_test_too_many_ops();
	if (!ret || (ret < 0 && errno != EINVAL)) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	return 0;
}

/* Use 64kB len, largest page size known on Linux. */
static int test_memcpy_single_too_large(void)
{
	int i, ret;
	char buf1[TESTBUFLEN_PAGE_MAX + 1];
	char buf2[TESTBUFLEN_PAGE_MAX + 1];
	const char *test_name = "test_memcpy_single_too_large";

	printf("Testing %s\n", test_name);

	/* Test memcpy */
	for (i = 0; i < TESTBUFLEN_PAGE_MAX + 1; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN_PAGE_MAX + 1);
	ret = test_memcpy_op(buf2, buf1, TESTBUFLEN_PAGE_MAX + 1);
	if (!ret || (ret < 0 && errno != EINVAL)) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	return 0;
}

static int test_memcpy_single_ok_sum_too_large_op(void *dst, void *src, size_t len)
{
	struct cpu_op opvec[] = {
		[0] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.dst, dst),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.src, src),
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
		[1] = {
			.op = CPU_MEMCPY_OP,
			.len = len,
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.dst, dst),
			CPU_OP_FIELD_u32_u64_INIT_ONSTACK(.u.memcpy_op.src, src),
			.u.memcpy_op.expect_fault_dst = 0,
			.u.memcpy_op.expect_fault_src = 0,
		},
	};
	int ret, cpu;

	do {
		cpu = cpu_op_get_current_cpu();
		ret = cpu_opv(opvec, ARRAY_SIZE(opvec), cpu, 0);
	} while (ret == -1 && errno == EAGAIN);

	return ret;
}

static int test_memcpy_single_ok_sum_too_large(void)
{
	int i, ret;
	char buf1[TESTBUFLEN];
	char buf2[TESTBUFLEN];
	const char *test_name = "test_memcpy_single_ok_sum_too_large";

	printf("Testing %s\n", test_name);

	/* Test memcpy */
	for (i = 0; i < TESTBUFLEN; i++)
		buf1[i] = (char)i;
	memset(buf2, 0, TESTBUFLEN);
	ret = test_memcpy_single_ok_sum_too_large_op(buf2, buf1, TESTBUFLEN);
	if (!ret || (ret < 0 && errno != EINVAL)) {
		printf("%s returned with %d, errno: %s\n",
			test_name, ret, strerror(errno));
		exit(-1);
	}
	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;

	ret |= test_compare_eq_same();
	ret |= test_compare_eq_diff();
	ret |= test_compare_ne_same();
	ret |= test_compare_ne_diff();
	ret |= test_2compare_eq_index();
	ret |= test_2compare_ne_index();
	ret |= test_memcpy();
	ret |= test_memcpy_u32();
	ret |= test_memcpy_mb_memcpy();
	ret |= test_add();
	ret |= test_two_add();
	ret |= test_or();
	ret |= test_and();
	ret |= test_xor();
	ret |= test_lshift();
	ret |= test_rshift();
	ret |= test_cmpxchg_success();
	ret |= test_cmpxchg_fail();
	ret |= test_memcpy_fault();
	ret |= test_unknown_op();
	ret |= test_max_ops();
	ret |= test_too_many_ops();
	ret |= test_memcpy_single_too_large();
	ret |= test_memcpy_single_ok_sum_too_large();

	return ret;
}
