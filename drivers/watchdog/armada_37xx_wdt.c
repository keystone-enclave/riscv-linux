/*
 * drivers/watchdog/armada_37xx_wdt.c
 *
 * Watchdog driver for Marvell Armada 37xx SoCs
 *
 * Author: Marek Behun <marek.behun@nic.cz>
 *
 * This file is licensed under  the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/watchdog.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <asm/io.h>

/*
 * There are four counters that can be used for watchdog on Armada 37xx.
 * The adresses for counter control registers are register base plus ID*0x10,
 * where ID is 0, 1, 2 or 3.
 * In this driver we use ID 1. Marvell's Linux also uses this ID by default,
 * and the U-Boot driver written simultaneosly by the same author as this
 * driver also uses ID 1.
 * Maybe in the future we could change this driver to support other counters,
 * depending on the device tree, but I don't think this is necessary.
 *
 * Note that CNTR_ID cannot be 3, because the third counter is an increment
 * counter, and this driver is written to support decrementing counters only.
 */

#define CNTR_ID				1

#define CNTR_CTRL			(CNTR_ID * 0x10)
#define CNTR_CTRL_ENABLE		0x0001
#define CNTR_CTRL_ACTIVE		0x0002
#define CNTR_CTRL_MODE_MASK		0x000c
#define CNTR_CTRL_MODE_ONESHOT		0x0000
#define CNTR_CTRL_PRESCALE_MASK		0xff00
#define CNTR_CTRL_PRESCALE_MIN		2
#define CNTR_CTRL_PRESCALE_SHIFT	8

#define CNTR_COUNT_LOW			(CNTR_CTRL + 0x4)
#define CNTR_COUNT_HIGH			(CNTR_CTRL + 0x8)

#define WDT_TIMER_SELECT_MASK		0xf
#define WDT_TIMER_SELECT		(1 << CNTR_ID)

#define WATCHDOG_TIMEOUT		120

static unsigned int timeout = WATCHDOG_TIMEOUT;
module_param(timeout, int, 0);
MODULE_PARM_DESC(timeout, "Watchdog timeout in seconds (default="
			  __MODULE_STRING(WATCHDOG_TIMEOUT) ")");

static bool nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, bool, 0);
MODULE_PARM_DESC(nowayout, "Watchdog cannot be stopped once started (default="
			   __MODULE_STRING(WATCHDOG_NOWAYOUT) ")");

struct armada_37xx_watchdog {
	struct watchdog_device wdt;
	void __iomem *sel_reg;
	void __iomem *reg;
	u64 timeout; /* in clock ticks */
	unsigned long clk_rate;
	struct clk *clk;
};

static u64 get_counter_value(struct armada_37xx_watchdog *dev)
{
	u64 val;

	val = readl(dev->reg + CNTR_COUNT_HIGH);
	val = (val << 32) | readl(dev->reg + CNTR_COUNT_LOW);

	return val;
}

static void set_counter_value(struct armada_37xx_watchdog *dev)
{
	writel(dev->timeout & 0xffffffff, dev->reg + CNTR_COUNT_LOW);
	writel(dev->timeout >> 32, dev->reg + CNTR_COUNT_HIGH);
}

static void armada_37xx_wdt_counter_enable(struct armada_37xx_watchdog *dev)
{
	u32 reg;

	reg = readl(dev->reg + CNTR_CTRL);
	reg |= CNTR_CTRL_ENABLE;
	writel(reg, dev->reg + CNTR_CTRL);
}

static void armada_37xx_wdt_counter_disable(struct armada_37xx_watchdog *dev)
{
	u32 reg;

	reg = readl(dev->reg + CNTR_CTRL);
	reg &= ~CNTR_CTRL_ENABLE;
	writel(reg, dev->reg + CNTR_CTRL);
}

static int armada_37xx_wdt_ping(struct watchdog_device *wdt)
{
	struct armada_37xx_watchdog *dev = watchdog_get_drvdata(wdt);

	armada_37xx_wdt_counter_disable(dev);
	set_counter_value(dev);
	armada_37xx_wdt_counter_enable(dev);

	return 0;
}

static unsigned int armada_37xx_wdt_get_timeleft(struct watchdog_device *wdt)
{
	struct armada_37xx_watchdog *dev = watchdog_get_drvdata(wdt);
	unsigned int res;

	res = get_counter_value(dev) * CNTR_CTRL_PRESCALE_MIN / dev->clk_rate;

	return res;
}

static int armada_37xx_wdt_set_timeout(struct watchdog_device *wdt,
				       unsigned int timeout)
{
	struct armada_37xx_watchdog *dev = watchdog_get_drvdata(wdt);

	wdt->timeout = timeout;

	/*
	 * Compute the timeout in clock rate. We use smallest possible prescaler,
	 * which divides the clock rate by 2 (CNTR_CTRL_PRESCALE_MIN).
	 */
	dev->timeout = (u64)dev->clk_rate * timeout / CNTR_CTRL_PRESCALE_MIN;

	return 0;
}

static bool armada_37xx_wdt_is_running(struct armada_37xx_watchdog *dev)
{
	u32 reg;

	reg = readl(dev->sel_reg);
	if ((reg & WDT_TIMER_SELECT_MASK) != WDT_TIMER_SELECT)
		return false;

	reg = readl(dev->reg + CNTR_CTRL);
	return !!(reg & CNTR_CTRL_ACTIVE);
}

static int armada_37xx_wdt_start(struct watchdog_device *wdt)
{
	struct armada_37xx_watchdog *dev = watchdog_get_drvdata(wdt);
	u32 reg;

	reg = readl(dev->reg + CNTR_CTRL);

	if (reg & CNTR_CTRL_ACTIVE)
		return -EBUSY;

	/* set mode */
	reg = (reg & ~CNTR_CTRL_MODE_MASK) | CNTR_CTRL_MODE_ONESHOT;

	/* set prescaler to the min value of 2 */
	reg &= ~CNTR_CTRL_PRESCALE_MASK;
	reg |= CNTR_CTRL_PRESCALE_MIN << CNTR_CTRL_PRESCALE_SHIFT;

	writel(reg, dev->reg + CNTR_CTRL);

	set_counter_value(dev);

	writel(WDT_TIMER_SELECT, dev->sel_reg);
	armada_37xx_wdt_counter_enable(dev);

	return 0;
}

static int armada_37xx_wdt_stop(struct watchdog_device *wdt)
{
	struct armada_37xx_watchdog *dev = watchdog_get_drvdata(wdt);

	armada_37xx_wdt_counter_disable(dev);
	writel(0, dev->sel_reg);

	return 0;
}

static const struct watchdog_info armada_37xx_wdt_info = {
	.options = WDIOF_SETTIMEOUT | WDIOF_KEEPALIVEPING | WDIOF_MAGICCLOSE,
	.identity = "Armada 37xx Watchdog",
};

static const struct watchdog_ops armada_37xx_wdt_ops = {
	.owner = THIS_MODULE,
	.start = armada_37xx_wdt_start,
	.stop = armada_37xx_wdt_stop,
	.ping = armada_37xx_wdt_ping,
	.set_timeout = armada_37xx_wdt_set_timeout,
	.get_timeleft = armada_37xx_wdt_get_timeleft,
};

static int armada_37xx_wdt_probe(struct platform_device *pdev)
{
	struct armada_37xx_watchdog *dev;
	struct resource *res;
	int ret;

	dev = devm_kzalloc(&pdev->dev, sizeof(struct armada_37xx_watchdog),
			   GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->wdt.info = &armada_37xx_wdt_info;
	dev->wdt.ops = &armada_37xx_wdt_ops;
	dev->wdt.min_timeout = 1;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;
	dev->sel_reg = devm_ioremap(&pdev->dev, res->start,
				    resource_size(res));

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res)
		return -ENODEV;
	dev->reg = devm_ioremap(&pdev->dev, res->start, resource_size(res));

	/* init clock */
	dev->clk = clk_get(&pdev->dev, NULL);
	if (IS_ERR(dev->clk))
		return PTR_ERR(dev->clk);

	ret = clk_prepare_enable(dev->clk);
	if (ret) {
		clk_put(dev->clk);
		return ret;
	}

	dev->clk_rate = clk_get_rate(dev->clk);

	/*
	 * Since the timeout in seconds is given as 32 bit unsigned int, and
	 * the counters hold 64 bit values, even after multiplication by clock
	 * rate the counter can hold timeout of UINT_MAX seconds.
	 */
	dev->wdt.min_timeout = 0;
	dev->wdt.max_timeout = UINT_MAX;
	dev->wdt.parent = &pdev->dev;

	/* default value, possibly override by module parameter or dtb */
	dev->wdt.timeout = WATCHDOG_TIMEOUT;
	watchdog_init_timeout(&dev->wdt, timeout, &pdev->dev);

	platform_set_drvdata(pdev, &dev->wdt);
	watchdog_set_drvdata(&dev->wdt, dev);

	armada_37xx_wdt_set_timeout(&dev->wdt, dev->wdt.timeout);

	if (armada_37xx_wdt_is_running(dev))
		set_bit(WDOG_HW_RUNNING, &dev->wdt.status);
	else
		armada_37xx_wdt_stop(&dev->wdt);

	watchdog_set_nowayout(&dev->wdt, nowayout);
	ret = watchdog_register_device(&dev->wdt);
	if (ret)
		goto disable_clk;

	dev_info(&pdev->dev, "Initial timeout %d sec%s\n",
		 dev->wdt.timeout, nowayout ? ", nowayout" : "");

	return 0;

disable_clk:
	clk_disable_unprepare(dev->clk);
	clk_put(dev->clk);
	return ret;
}

static int armada_37xx_wdt_remove(struct platform_device *pdev)
{
	struct watchdog_device *wdt = platform_get_drvdata(pdev);
	struct armada_37xx_watchdog *dev = watchdog_get_drvdata(wdt);

	watchdog_unregister_device(wdt);
	clk_disable_unprepare(dev->clk);
	clk_put(dev->clk);
	return 0;
}

static void armada_37xx_wdt_shutdown(struct platform_device *pdev)
{
	struct watchdog_device *wdt = platform_get_drvdata(pdev);

	armada_37xx_wdt_stop(wdt);
}

static int __maybe_unused armada_37xx_wdt_suspend(struct device *dev)
{
	struct watchdog_device *wdt = dev_get_drvdata(dev);

	return armada_37xx_wdt_stop(wdt);
}

static int __maybe_unused armada_37xx_wdt_resume(struct device *dev)
{
	struct watchdog_device *wdt = dev_get_drvdata(dev);

	if (watchdog_active(wdt))
		return armada_37xx_wdt_start(wdt);

	return 0;
}

static const struct dev_pm_ops armada_37xx_wdt_dev_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(armada_37xx_wdt_suspend,
				armada_37xx_wdt_resume)
};

#ifdef CONFIG_OF
static const struct of_device_id armada_37xx_wdt_match[] = {
	{ .compatible = "marvell,armada-3700-wdt", },
	{},
};
MODULE_DEVICE_TABLE(of, armada_37xx_wdt_match);
#endif

static struct platform_driver armada_37xx_wdt_driver = {
	.probe		= armada_37xx_wdt_probe,
	.remove		= armada_37xx_wdt_remove,
	.shutdown	= armada_37xx_wdt_shutdown,
	.driver		= {
		.name	= "armada_37xx_wdt",
		.of_match_table = of_match_ptr(armada_37xx_wdt_match),
		.pm = &armada_37xx_wdt_dev_pm_ops,
	},
};

module_platform_driver(armada_37xx_wdt_driver);

MODULE_AUTHOR("Marek Behun <marek.behun@nic.cz>");
MODULE_DESCRIPTION("Armada 37xx CPU Watchdog");

MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:armada_37xx_wdt");
