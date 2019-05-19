OPAL_PCI_GET_XIVE_REISSUE and OPAL_PCI_SET_XIVE_REISSUE
-------------------------------------------------------

static int64_t opal_pci_get_xive_reissue(uint64_t phb_id __unused,
					 uint32_t xive_number __unused,
					 uint8_t *p_bit __unused,
					 uint8_t *q_bit __unused)

static int64_t opal_pci_set_xive_reissue(uint64_t phb_id __unused,
					 uint32_t xive_number __unused,
					 uint8_t p_bit __unused,
					 uint8_t q_bit __unused)


Both of these calls are remnants from previous OPAL versions, calling either
of them shall return OPAL_UNSUPPORTED.

