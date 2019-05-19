IODA PE Setup Sequences
-----------------------

(WARNING: this was rescued from old internal documentation. Needs verification)

To setup basic PE mappings, the host performs this basic sequence:

    For ibm,opal-ioda2, prior to allocating PHB resources to PEs, the host must
    allocate memory for PE structures and then calls
    opal_pci_set_phb_table_memory( phb_id, rtt_addr, ivt_addr, ivt_len,
    rrba_addr, peltv_addr) to define them to the PHB. OPAL returns
    OPAL_UNSUPPORTED status for ibm,opal-ioda PHBs.

    The host calls opal_pci_set_pe( phb_id, pe_number, bus, dev, func,
    validate_mask, bus_mask, dev_mask, func mask) to map a PE to a PCI RID or
    range of RIDs in the same PE domain.

    The host calls opal_pci_set_peltv(phb_id, parent_pe, child_pe, state) to
    set a parent PELT vector bit for the child PE argument to 1 (a child of the
    parent) or 0 (not in the parent PE domain).

IODA MMIO Setup Sequences
-------------------------

(WARNING: this was rescued from old internal documentation. Needs verification)


    The host calls opal_pci_phb_mmio_enable( phb_id, window_type, window_num, 0x0) to disable the MMIO window.

    The host calls opal_pci_set_phb_mmio_window( phb_id, mmio_window, starting_real_address, starting_pci_address, segment_size) to change the MMIO window location in PCI and/or processor real address space, or to change the size -- and corresponding window size -- of a particular MMIO window.

    The host calls opal_pci_map_pe_mmio_window( pe_number, mmio_window, segment_number) to map PEs to window segments, for each segment mapped to each PE.

    The host calls opal_pci_phb_mmio_enable( phb_id, window_type, window_num, 0x1) to enable the MMIO window.

IODA MSI Setup Sequences
------------------------

(WARNING: this was rescued from old internal documentation. Needs verification)

To setup MSIs:


1.    For ibm,opal-ioda PHBs, the host chooses an MVE for a PE to use and calls opal_pci_set_mve( phb_id, mve_number, pe_number,) to setup the MVE for the PE number. HAL treats this call as a NOP and returns hal_success status for ibm,opal-ioda2 PHBs.

2.    the host chooses an XIVE to use with a PE and calls

      a. opal_pci_set_xive_pe( phb_id, xive_number, pe_number) to authorize that PE to signal that XIVE as an interrupt. The host must call this function for each XIVE assigned to a particular PE, but may use this call for all XIVEs prior to calling opel_pci_set_mve() to bind the PE XIVEs to an MVE.For MSI conventional, the host must bind a unique MVE for each sequential set of 32 XIVEs.

      b. The host forms the interrupt_source_number from the combination of the device tree MSI property base BUID and XIVE number, as an input to opal_set_xive(interrupt_source_number, server_number, priority) and opal_get_xive(interrupt_source_number, server_number, priority) to set or return the server and priority numbers within an XIVE.

      c. opal_get_msi_64[32](phb_id, mve_number, xive_num, msi_range, msi_address, message_data) to determine the MSI DMA address (32 or 64 bit) and message data value for that xive.

        For MSI conventional, the host uses this for each sequential power of 2 set of 1 to 32 MSIs, to determine the MSI DMA address and starting message data value for that MSI range. For MSI-X, the host calls this uniquely for each MSI interrupt with an msi_range input value of 1.


3.    For ibm,opal-ioda PHBs, once the MVE and XIVRs are setup for a PE, the host calls opal_pci_set_mve_enable( phb_id, mve_number, state)to enable that MVE to be a valid target of MSI DMAs. The host may also call this function to disable an MVE when changing PE domains or states.

IODA DMA Setup Sequences
------------------------

(WARNING: this was rescued from old internal documentation. Needs verification)



To Manage DMA Windows :


1.    The host calls opal_pci_map_pe_dma_window( phb_id, dma_window_number, pe_number, tce_levels, tce_table_addr, tce_table_size, tce_page_size, utin64_t* pci_start_addr ) to setup a DMA window for a PE to translate through a TCE table structure in KVM memory.

2.    The host calls opal_pci_map_pe_dma_window_real( phb_id, dma_window_number, pe_number, mem_low_addr, mem_high_addr) to setup a DMA window for a PE that is translated (but validated by the PHB as an untranlsated address space authorized to this PE).
