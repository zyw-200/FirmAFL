#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x3955bf8e, "module_layout" },
	{ 0x44e278f1, "unregister_jprobe" },
	{ 0x9f3d9686, "register_jprobe" },
	{ 0xea147363, "printk" },
	{ 0xc86fc36, "init_task" },
	{ 0x1b9aca3f, "jprobe_return" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";

