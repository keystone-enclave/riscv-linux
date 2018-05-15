// SPDX-License-Identifier: GPL-2.0+
/*
 * OWL SoC's GPIO driver
 *
 * Copyright (c) 2018 Linaro Ltd.
 * Author: Manivannan Sadhasivam <manivannan.sadhasivam@linaro.org>
 */

#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/gpio/driver.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#define GPIO_OUTEN	0x0000
#define GPIO_INEN	0x0004
#define GPIO_DAT	0x0008

struct owl_gpio {
	struct gpio_chip gpio;
	void __iomem *base;
	spinlock_t lock;
};

static void owl_gpio_update_reg(void __iomem *base, unsigned int pin, int flag)
{
	u32 val;

	val = readl_relaxed(base);

	if (flag)
		val |= BIT(pin);
	else
		val &= ~BIT(pin);

	writel_relaxed(val, base);
}

static int owl_gpio_request(struct gpio_chip *chip, unsigned int offset)
{
	struct owl_gpio *gpio = gpiochip_get_data(chip);

	/*
	 * GPIOs have higher priority over other modules, so either setting
	 * them as OUT or IN is sufficient
	 */
	spin_lock(&gpio->lock);
	owl_gpio_update_reg(gpio->base + GPIO_OUTEN, offset, true);
	spin_unlock(&gpio->lock);

	return 0;
}

static void owl_gpio_free(struct gpio_chip *chip, unsigned int offset)
{
	struct owl_gpio *gpio = gpiochip_get_data(chip);

	spin_lock(&gpio->lock);
	/* disable gpio output */
	owl_gpio_update_reg(gpio->base + GPIO_OUTEN, offset, false);

	/* disable gpio input */
	owl_gpio_update_reg(gpio->base + GPIO_INEN, offset, false);
	spin_unlock(&gpio->lock);
}

static int owl_gpio_get(struct gpio_chip *chip, unsigned int offset)
{
	struct owl_gpio *gpio = gpiochip_get_data(chip);
	u32 val;

	spin_lock(&gpio->lock);
	val = readl_relaxed(gpio->base + GPIO_DAT);
	spin_unlock(&gpio->lock);

	return !!(val & BIT(offset));
}

static void owl_gpio_set(struct gpio_chip *chip, unsigned int offset, int value)
{
	struct owl_gpio *gpio = gpiochip_get_data(chip);

	spin_lock(&gpio->lock);
	owl_gpio_update_reg(gpio->base + GPIO_DAT, offset, value);
	spin_unlock(&gpio->lock);
}

static int owl_gpio_direction_input(struct gpio_chip *chip, unsigned int offset)
{
	struct owl_gpio *gpio = gpiochip_get_data(chip);

	spin_lock(&gpio->lock);
	owl_gpio_update_reg(gpio->base + GPIO_OUTEN, offset, false);
	owl_gpio_update_reg(gpio->base + GPIO_INEN, offset, true);
	spin_unlock(&gpio->lock);

	return 0;
}

static int owl_gpio_direction_output(struct gpio_chip *chip,
				unsigned int offset, int value)
{
	struct owl_gpio *gpio = gpiochip_get_data(chip);

	spin_lock(&gpio->lock);
	owl_gpio_update_reg(gpio->base + GPIO_INEN, offset, false);
	owl_gpio_update_reg(gpio->base + GPIO_OUTEN, offset, true);
	owl_gpio_update_reg(gpio->base + GPIO_DAT, offset, value);
	spin_unlock(&gpio->lock);

	return 0;
}

static int owl_gpio_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct owl_gpio *gpio;
	u32 ngpios;
	int ret;

	gpio = devm_kzalloc(dev, sizeof(*gpio), GFP_KERNEL);
	if (!gpio)
		return -ENOMEM;

	gpio->base = of_iomap(dev->of_node, 0);
	if (IS_ERR(gpio->base))
		return PTR_ERR(gpio->base);

	/*
	 * Get the number of gpio's for this bank. If none specified,
	 * then fall back to 32.
	 */
	ret = of_property_read_u32(dev->of_node, "ngpios", &ngpios);
	if (ret)
		ngpios = 32;

	spin_lock_init(&gpio->lock);

	gpio->gpio.request = owl_gpio_request;
	gpio->gpio.free = owl_gpio_free;
	gpio->gpio.get = owl_gpio_get;
	gpio->gpio.set = owl_gpio_set;
	gpio->gpio.direction_input = owl_gpio_direction_input;
	gpio->gpio.direction_output = owl_gpio_direction_output;

	gpio->gpio.base = -1;
	gpio->gpio.parent = dev;
	gpio->gpio.label = dev_name(dev);
	gpio->gpio.ngpio = ngpios;

	platform_set_drvdata(pdev, gpio);

	ret = devm_gpiochip_add_data(dev, &gpio->gpio, gpio);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to register gpiochip\n");
		return ret;
	}

	return 0;
}

static const struct of_device_id owl_gpio_of_match[] = {
	{ .compatible = "actions,s900-gpio", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, owl_gpio_of_match);

static struct platform_driver owl_gpio_driver = {
	.driver		= {
		.name	= "owl-gpio",
		.of_match_table = owl_gpio_of_match,
	},
	.probe		= owl_gpio_probe,
};
module_platform_driver(owl_gpio_driver);

MODULE_AUTHOR("Manivannan Sadhasivam <manivannan.sadhasivam@linaro.org>");
MODULE_DESCRIPTION("Actions Semi OWL SoCs GPIO driver");
MODULE_LICENSE("GPL");
