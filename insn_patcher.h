/*
 * instruction length decoder (written by kaitek, modified by mercurysquad)
 * voodoo xnu kernel
 */

#ifndef _DISASM_H
#define _DISASM_H

#include <stdint.h>

/* EXTENDED_PATCHER enables FISTTP/LDDQU patching support */

#ifdef EXTENDED_PATCHER
# define LDDQU			0xf00ff2
#endif
#define CPUID			0xa20f
#define SYSENTER		0x340f

/* INSN_* are possible return codes from get_insn_length if length can't be found */
#define INSN_INVALID		0
#define INSN_UNSUPPORTED	(-1)

/* STATUS_* are possible status codes written bit-packed to the location specified
 * by the status argument to get_insn_length */
#define STATUS_NEEDS_PATCH     (1 << 0)
#define STATUS_PADDING         (1 << 1)
#ifdef EXTENDED_PATCHER
# define STATUS_REST           (1 << 2)
#endif

struct segment_command *getsegforpatch(struct mach_header *header, const char *seg_name);
struct segment_command_64 *getsegforpatch_64(struct mach_header_64 *header, const char *seg_name);

struct section *getsectforpatch(struct mach_header *header, const char *segname, const char *sectname);
struct section_64 *getsectforpatch_64(struct mach_header_64 *header, const char *segname, const char *sectname);

int32_t get_insn_length(uint8_t *insn, boolean_t is_64bit, uint8_t *status);

boolean_t patch_insn(uint8_t *insn, boolean_t verbose, boolean_t is_64bit);

uint32_t scan_text_section(uint8_t *start, uint64_t size, uint64_t text_addr,
		boolean_t should_patch, boolean_t abi_is_64, boolean_t verbose,
		uint32_t *num_patches_out);

kern_return_t patch_text_segment(uint8_t *addr, mach_vm_offset_t map_addr,
		mach_vm_size_t map_size, boolean_t abi_is_64, boolean_t seg_is_64,
		boolean_t verbose, boolean_t *bypass, uint32_t *num_patches_out,
		uint32_t *num_bad_out);

/* magic numbers fine-tuned for accurate disassembly; don't mess with these unless
 * you really know what you are doing. */
#define REST_SIZE		25
#define PRESCAN_SIZE		1000
#define PRESCAN_MAX_BAD		20

uint8_t *check_sysenter_trap(uint8_t *insn);
void patch_sysenter_trap(uint8_t *begin);

#endif
