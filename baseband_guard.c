#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/namei.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/hashtable.h>
#include <linux/blkdev.h>
#include <linux/lsm_hooks.h>

// --- kernel_compat-1.h 内容开始 ---
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
static inline int lookup_bdev_compat(char *path, dev_t *out) {
    struct block_device *bdev;

    if (!path || !out) {
        return 1;
    }

    bdev = lookup_bdev(path);
	if (IS_ERR(bdev))
		return 1;
	*out = bdev->bd_dev;
	bdput(bdev);
	return 0;
}
#else
static inline int lookup_bdev_compat(char *path, dev_t *out) {
    dev_t dev;
	int ret;

    if (!path || !out) {
        return 1;
    }

    ret = lookup_bdev(path, &dev);
	if (ret) return ret;

	*out = dev;
	return 0;
}
#endif

// https://github.com/torvalds/linux/commit/22ae8ce8b89241c94ac00c237752c0ffa37ba5ae
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0) 

static bool bbg_is_named_device(dev_t dev, const char *name_prefix)
{
    struct block_device *bdev;
    bool match = false;

    bdev = blkdev_get_by_dev(dev, FMODE_READ, THIS_MODULE);
    if (IS_ERR(bdev))
        return false;

    if (bdev->bd_disk && name_prefix) {
        const char *disk_name = bdev->bd_disk->disk_name;
        size_t prefix_len = strlen(name_prefix);

        if (strncmp(disk_name, name_prefix, prefix_len) == 0) {
            match = true;
        }
    }

    blkdev_put(bdev, FMODE_READ);
    return match;
}
#else

static bool bbg_is_named_device(dev_t dev, const char *name_prefix)
{
    struct block_device *bdev;
    bool match = false;

// https://github.com/torvalds/linux/commit/5f33b5226c9d92359e58e91ad0bf0c1791da36a1
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,15,0)
    bdev = blkdev_get_no_open(dev);
#else
    bdev = blkdev_get_no_open(dev, true);
#endif

    if (IS_ERR(bdev))
        return false;

    if (bdev->bd_disk && name_prefix) {
        const char *disk_name = bdev->bd_disk->disk_name;
        size_t prefix_len = strlen(name_prefix);
        match = (strncmp(disk_name, name_prefix, prefix_len) == 0);
    }

    blkdev_put_no_open(bdev);

    return match;
}

#endif

#ifdef CONFIG_SECURITY_SELINUX

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
struct task_security_struct {
	u32 osid;		/* SID prior to last execve */
	u32 sid;		/* current SID */
	u32 exec_sid;		/* exec SID */
	u32 create_sid;		/* fscreate SID */
	u32 keycreate_sid;	/* keycreate SID */
	u32 sockcreate_sid;	/* fscreate SID */
};
static inline void security_cred_getsecid_compat(const struct cred *c, u32 *secid) {
    const struct task_security_struct *tsec;

    if (!c || !secid) {
        return;
    }

	tsec = c->security;
	*secid = tsec->sid;
}
#else
static inline void security_cred_getsecid_compat(const struct cred *c, u32 *secid) {
    security_cred_getsecid(c, secid);
}
#endif


#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
const struct lsm_id bbg_lsmid = {
	.name = "baseband_guard",
	.id = 995,
};
#endif

static inline void __init security_add_hooks_compat(struct security_hook_list *hooks, int count) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
	security_add_hooks(hooks, count, &bbg_lsmid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
	security_add_hooks(hooks, count, "baseband_guard");
#else
	security_add_hooks(hooks, count);
#endif

}
// --- kernel_compat-1.h 内容结束 ---

// --- Definitions from the original file ---
#define BB_ENFORCING 1

#if CONFIG_BBG_ANTI_SPOOF_DOMAIN == 1
#define BB_ANTI_SPOOF_NO_TRUST_PERMISSIVE_ONCE 0
#define BB_ANTI_SPOOF_DISABLE_PERMISSIVE 1
#elif CONFIG_BBG_ANTI_SPOOF_DOMAIN == 2
#define BB_ANTI_SPOOF_NO_TRUST_PERMISSIVE_ONCE 1
#define BB_ANTI_SPOOF_DISABLE_PERMISSIVE 0
#else
#define BB_ANTI_SPOOF_NO_TRUST_PERMISSIVE_ONCE 0
#define BB_ANTI_SPOOF_DISABLE_PERMISSIVE 0
#endif

#define bb_pr(fmt, ...)    pr_debug("baseband_guard: " fmt, ##__VA_ARGS__)
#define bb_pr_rl(fmt, ...) pr_info_ratelimited("baseband_guard: " fmt, ##__VA_ARGS__)

#define BB_BYNAME_DIR "/dev/block/by-name"
// --- End Definitions ---

// --- Data Structures and Functions (Allowed lists, ioctl checks, logging, etc.) ---
static const char * const allowed_domain_substrings[] = {
	"update_engine", "platform_app", "fastbootd",
#ifdef CONFIG_BBG_ALLOW_IN_RECOVERY
	"recovery",
#endif
	"rmt_storage", "oplus", "oppo", "feature", "swap", "system_perf_init",
	"hal_bootctl_default", "fsck", "vendor", "mi_ric", "system_server",
	"minidumpreader", "bspFwUpdate", "u:r:vold:s0", "kernel", "tee", "gsid",
	"snapuserd",
};
static const size_t allowed_domain_substrings_cnt = ARRAY_SIZE(allowed_domain_substrings);

static const char * const allowlist_names[] = {
#ifndef CONFIG_BBG_BLOCK_BOOT
	"boot", "init_boot",
#endif
	"dtbo", "vendor_boot", "userdata", "cache", "metadata", "misc",
	"vbmeta", "vbmeta_system", "vbmeta_vendor",
#ifndef BBG_BLOCK_RECOVERY
	"recovery"
#endif
};
static const size_t allowlist_cnt = ARRAY_SIZE(allowlist_names);

extern char *saved_command_line;
static const char *slot_suffix_from_cmdline(void)
{
	const char *p = saved_command_line;
	if (!p) return NULL;
	p = strstr(p, "androidboot.slot_suffix=");
	if (!p) return NULL;
	p += strlen("androidboot.slot_suffix=");
	if (p[0] == '_' && (p[1] == 'a' || p[1] == 'b')) return (p[1] == 'a') ? "_a" : "_b";
	return NULL;
}

static bool inline resolve_byname_dev(const char *name, dev_t *out)
{
	char *path;
	dev_t dev;
	int ret;

	if (!name || !out) return false;

	path = kasprintf(GFP_KERNEL, "%s/%s", BB_BYNAME_DIR, name);
	if (!path) return false;

	ret = lookup_bdev_compat(path, &dev);
	kfree(path);
	if (ret) return false;

	*out = dev;
	return true;
}

struct allow_node { dev_t dev; struct hlist_node h; };
DEFINE_HASHTABLE(allowed_devs, 7);

static bool allow_has(dev_t dev)
{
	struct allow_node *p;
	hash_for_each_possible(allowed_devs, p, h, (u64)dev)
		if (p->dev == dev) return true;
	return false;
}

static void allow_add(dev_t dev)
{
	struct allow_node *n;
	if (!dev || allow_has(dev)) return;
	n = kmalloc(sizeof(*n), GFP_ATOMIC);
	if (!n) return;
	n->dev = dev;
	hash_add(allowed_devs, &n->h, (u64)dev);
	bb_pr("allow-cache dev %u:%u\n", MAJOR(dev), MINOR(dev));
}

static inline bool is_allowed_partition_dev_resolve(dev_t cur)
{
	size_t i;
	dev_t dev;
	const char *suf = slot_suffix_from_cmdline();

	for (i = 0; i < allowlist_cnt; i++) {
		const char *n = allowlist_names[i];
		bool ok = false;

		if (resolve_byname_dev(n, &dev) && dev == cur) 
			return true;

		if (!ok && suf) {
			char *nm = kasprintf(GFP_ATOMIC, "%s%s", n, suf);
			if (nm) {
				ok = resolve_byname_dev(nm, &dev);
				kfree(nm);
				if (ok && dev == cur) return true;
			}
		}
		if (!ok) {
			char *na = kasprintf(GFP_ATOMIC, "%s_a", n);
			char *nb = kasprintf(GFP_ATOMIC, "%s_b", n);
			if (na) {
				ok = resolve_byname_dev(na, &dev);
				kfree(na);
				if (ok && dev == cur) { if (nb) kfree(nb); return true; }
			}
			if (nb) {
				ok = resolve_byname_dev(nb, &dev);
				kfree(nb);
				if (ok && dev == cur) return true;
			}
		}
	}
	return false;
}

static bool is_zram_device(dev_t dev)
{
	return bbg_is_named_device(dev, "zram");
}

static bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_zram_device(cur)) {
		allow_add(cur);
		return true;
	}
	if (is_allowed_partition_dev_resolve(cur)) {
		allow_add(cur);
		return true;
	}
	return false;
}

#if BB_ANTI_SPOOF_NO_TRUST_PERMISSIVE_ONCE
static bool bbg_recently_permissive __read_mostly = false;
#endif

static bool current_domain_allowed(void)
{
#ifdef CONFIG_SECURITY_SELINUX
	u32 sid = 0;
	char *ctx = NULL;
	u32 len = 0;
	bool ok = false;
	size_t i;

#if BB_ANTI_SPOOF_NO_TRUST_PERMISSIVE_ONCE
	if (unlikely(bbg_recently_permissive)) return false;
#endif

	security_cred_getsecid_compat(current_cred(), &sid);
	if (!sid) return false;
	if (security_secid_to_secctx(sid, &ctx, &len)) return false;
	if (!ctx || !len) goto out;

	for (i = 0; i < allowed_domain_substrings_cnt; i++) {
		const char *needle = allowed_domain_substrings[i];
		if (needle && *needle) {
			if (strnstr(ctx, needle, len)) { ok = true; break; }
		}
	}
out:
	if (ctx && len)
		security_release_secctx(ctx, len);
	return ok;
#else
	return false;
#endif
}

static const char *bbg_file_path(struct file *file, char *buf, int buflen)
{
	char *p;
	if (!file || !buf || buflen <= 0) return NULL;
	buf[0] = '\0';
	p = d_path(&file->f_path, buf, buflen);
	return IS_ERR(p) ? NULL : p;
}

static int bbg_get_cmdline(char *buf, int buflen)
{
	int n, i;
	if (!buf || buflen <= 0) return 0;
	n = get_cmdline(current, buf, buflen);
	if (n <= 0) return 0;
	for (i = 0; i < n - 1; i++) if (buf[i] == '\0') buf[i] = ' ';
	if (n < buflen) buf[n] = '\0';
	else buf[buflen - 1] = '\0';
	return n;
}

static void bbg_log_deny_detail(const char *why, struct file *file, unsigned int cmd_opt)
{
	u32 sid = 0;
	char *ctx = NULL;
	u32 len = 0;
	const int PATH_BUFLEN = 256;
	const int CMD_BUFLEN  = 256;

	char *pathbuf = kmalloc(PATH_BUFLEN, GFP_ATOMIC);
	char *cmdbuf  = kmalloc(CMD_BUFLEN,  GFP_ATOMIC);

	const char *path = pathbuf ? bbg_file_path(file, pathbuf, PATH_BUFLEN) : NULL;
	struct inode *inode = file ? file_inode(file) : NULL;
	dev_t dev = inode ? inode->i_rdev : 0;

	if (cmdbuf)
		bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

	security_cred_getsecid_compat(current_cred(), &sid);

	if (!sid || security_secid_to_secctx(sid, &ctx, &len) || !ctx || !len) {
		ctx = "unknown";
		len = strlen("unknown");
	}

	if (cmd_opt) {
		pr_info(
			"baseband_guard: deny %s cmd=0x%x dev=%u:%u path=%s pid=%d selinux_domain: %.*s comm=%s argv=\"%s\"\n",
			why, cmd_opt, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, len, ctx, current->comm,
			cmdbuf ? cmdbuf : "?");
	} else {
		pr_info(
			"baseband_guard: deny %s dev=%u:%u path=%s pid=%d selinux_domain: %.*s comm=%s argv=\"%s\"\n",
			why, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, len, ctx, current->comm,
			cmdbuf ? cmdbuf : "?");
	}

	kfree(cmdbuf);
	kfree(pathbuf);
}

static int deny(const char *why, struct file *file, unsigned int cmd_opt)
{
	if (!BB_ENFORCING) return 0;
	bbg_log_deny_detail(why, file, cmd_opt);
	bb_pr_rl("deny %s pid=%d comm=%s\n", why, current->pid, current->comm);
	return -EPERM;
}

static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;

	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (likely(current_domain_allowed()))
		return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("write to protected partition", file, 0);
}

static inline bool is_destructive_ioctl(unsigned int cmd)
{
	switch (cmd) {
	case BLKDISCARD:
	case BLKSECDISCARD:
	case BLKZEROOUT:
#ifdef BLKPG
	case BLKPG:
#endif
#ifdef BLKTRIM
	case BLKTRIM:
#endif
#ifdef BLKRRPART
	case BLKRRPART:
#endif
#ifdef BLKSETRO
	case BLKSETRO:
#endif
#ifdef BLKSETBADSECTORS
	case BLKSETBADSECTORS:
#endif
		return true;
	default:
		return false;
	}
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;

	if (!file) return 0;
	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (!is_destructive_ioctl(cmd))
		return 0;

	if (likely(current_domain_allowed()))
		return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("destructive ioctl on protected partition", file, cmd);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#endif

static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,      bb_file_permission),
	LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
	LSM_HOOK_INIT(file_ioctl_compat,    bb_file_ioctl_compat),
#endif
};

// Renamed and adapted to be a standard module init function
static int __init bbg_module_init(void)
{
	security_add_hooks_compat(bb_hooks, ARRAY_SIZE(bb_hooks));
	pr_info("baseband_guard: Loaded as a KernelPatchModule.\n");
	pr_info("baseband_guard power by https://t.me/qdykernel\n");
	pr_info("baseband_guard version: %s", "1.0"); 
	return 0;
}

// Added a module exit function (unloading LSM hooks is often complex/unsupported)
static void __exit bbg_module_exit(void)
{
	pr_info("baseband_guard: Unloading module. Hooks may remain active.\n");
}

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
// Retaining this function if the kernel has the CONFIG_SECURITY_SELINUX_DEVELOP
int bbg_process_setpermissive(void) {
#if BB_ANTI_SPOOF_NO_TRUST_PERMISSIVE_ONCE
	if (!bbg_recently_permissive) bbg_recently_permissive = true;
	return 0;
#elif BB_ANTI_SPOOF_DISABLE_PERMISSIVE
	return 1;
#else
	return 0;
#endif
}
#endif

// Retaining this function if the kernel has the CONFIG_BBG_DOMAIN_PROTECTION
int bbg_test_domain_transition(u32 target_secid) {
#ifdef CONFIG_BBG_DOMAIN_PROTECTION
	u32 sid = 0;
    char *ctx = NULL;
    u32 len = 0;
    int ok = 0;
	size_t i;

    security_cred_getsecid_compat(current_cred(), &sid);
    if (!sid) return 0;
    if (security_secid_to_secctx(sid, &ctx, &len)) return 0;

    if (ctx && len) {
        if (strnstr(ctx, ":su:", len)) {
            ok = 1;
        }
    }

    if (ctx && len)
        security_release_secctx(ctx, len);

	if (!ok) return 0;
	ok = 0;

	if (security_secid_to_secctx(target_secid, &ctx, &len)) return 0;
    if (!ctx || !len) goto out;

	for (i = 0; i < allowed_domain_substrings_cnt; i++) {
		const char *needle = allowed_domain_substrings[i];
		if (needle && *needle) {
			if (strnstr(ctx, needle, len)) { ok = 1; break; }
		}
	}
out:
	if (ok) {
            pr_info("baseband_guard: deny domain transition, target domain: %.*s, current PID: %d\n",
                    len, ctx, current->pid);
        }
	if (ctx && len)
		security_release_secctx(ctx, len);
    if (!BB_ENFORCING)
        return 0;

    return ok;
#else
    return 0;
#endif
}

// Use standard module macros instead of security_initcall/DEFINE_LSM
module_init(bbg_module_init);
module_exit(bbg_module_exit);

MODULE_DESCRIPTION("protect All Block & Power by TG@qdykernel (KernelPatchModule)");
MODULE_AUTHOR("秋刀鱼 & https://t.me/qdykernel");
MODULE_LICENSE("GPL v2");