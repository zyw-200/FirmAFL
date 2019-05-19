#ifndef PNOR_H
#define PNOR_H

#include <libflash/libffs.h>
#include <libflash/blocklevel.h>

struct pnor {
	char			*path;
	struct ffs_handle	*ffsh;
	uint32_t		size;
	uint32_t		erasesize;
	struct blocklevel_device *bl;
};

enum pnor_op {
	PNOR_OP_READ,
	PNOR_OP_WRITE,
};

extern int pnor_operation(struct pnor *pnor, const char *name,
			  uint64_t offset, void *data, size_t size,
			  enum pnor_op);

extern int pnor_init(struct pnor *pnor);
extern void pnor_close(struct pnor *pnor);

#endif /*PNOR_H*/
