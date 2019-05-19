#ifndef __XSCOM_P9_REGS_H__
#define __XSCOM_P9_REGS_H__

/* EX (core pair) registers, use XSCOM_ADDR_P9_EX to access */
#define P9X_EX_NCU_STATUS_REG			0x1100f
#define P9X_EX_NCU_SPEC_BAR			0x11010
#define   P9X_EX_NCU_SPEC_BAR_ENABLE		PPC_BIT(0)
#define   P9X_EX_NCU_SPEC_BAR_256K		PPC_BIT(1)
#define   P9X_EX_NCU_SPEC_BAR_ADDRMSK		0x0fffffffffffc000ull /* naturally aligned */
#define P9X_EX_NCU_DARN_BAR			0x11011

#endif /* __XSCOM_P9_REGS_H__ */
