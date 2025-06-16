/*
 * Directory to save the NAND backup to.
 *
 * File path format is $[BACKUP_DIR]/YYMMDD_$[SERIAL]_nand_??.bin
 */
#define BACKUP_DIR "/wii/backups"

/*
 * Disables saving the NAND backup.
 *
 * Intended to make sure /dev/flash patch is working. Title bar may turn green.
 */
//#define NANDDUMPER_READ_TEST

/*
 * Try to reload to this IOS instead of 58.
 *
 * Listing multiple IOS separated via commas could probably work, see load_startup_ios().
 */
//#define NANDDUMPER_FORCE_IOS
