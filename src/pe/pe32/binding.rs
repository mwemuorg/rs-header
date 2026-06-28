use crate::pe::loader::PeLoader;
use super::{HintNameItem, PE32};

impl PE32 {
    /// Bind the delay-load import table into guest memory via `loader`.
    pub fn delay_load_binding<L: PeLoader>(&mut self, raw: &[u8], loader: &mut L, base_addr: u32) {
        for i in 0..self.delay_load_dir.len() {
            let name = self.delay_load_dir[i].name.clone();
            if name.is_empty() {
                continue;
            }
            let name_table = self.delay_load_dir[i].name_table;
            let bound_delay_import_table = self.delay_load_dir[i].bound_delay_import_table;

            if loader.load_library(&name) == 0 {
                log::warn!("cannot find delay-load library `{}` (skipping)", name);
                continue;
            }

            let mut off_name = PE32::vaddr_to_off(&self.sect_hdr, name_table) as usize;
            let mut off_addr = PE32::vaddr_to_off(&self.sect_hdr, bound_delay_import_table) as usize;
            let mut rva = bound_delay_import_table;

            loop {
                if raw.len() <= off_name + 4 || raw.len() <= off_addr + 4 {
                    break;
                }

                let hint = HintNameItem::load(raw, off_name);
                let off2 = PE32::vaddr_to_off(&self.sect_hdr, hint.func_name_addr) as usize;
                if off2 == 0 {
                    off_name += HintNameItem::size();
                    off_addr += 4;
                    rva += 4;
                    continue;
                }
                let func_name = PE32::read_string(raw, off2 + 2);
                let real_addr = loader.resolve_api_name(&func_name);
                if real_addr == 0 {
                    break;
                }

                let patch_addr = base_addr as u64 + rva as u64;
                loader.write_dword(patch_addr, real_addr as u32);
                self.iat_names
                    .insert(real_addr as u32, format!("{}!{}", name, func_name));

                off_name += HintNameItem::size();
                off_addr += 4;
                rva += 4;
            }
        }
    }

    /// Bind the import address table into guest memory via `loader`.
    pub fn iat_binding<L: PeLoader>(&mut self, raw: &[u8], loader: &mut L, base_addr: u32) {
        log::debug!(
            "IAT binding started, {} import descriptors",
            self.image_import_descriptor.len()
        );

        for i in 0..self.image_import_descriptor.len() {
            let iim_name = self.image_import_descriptor[i].name.clone();
            if iim_name.is_empty() {
                continue;
            }
            let original_first_thunk = self.image_import_descriptor[i].original_first_thunk;
            let first_thunk = self.image_import_descriptor[i].first_thunk;

            if loader.load_library(&iim_name) == 0 {
                log::debug!("cannot find library `{}` (IAT binding skips it)", iim_name);
                continue;
            }

            let mut off_name = PE32::vaddr_to_off(&self.sect_hdr, original_first_thunk) as usize;
            let mut off_addr = PE32::vaddr_to_off(&self.sect_hdr, first_thunk) as usize;
            let mut rva = first_thunk;

            loop {
                if raw.len() <= off_name + 4 || raw.len() <= off_addr + 4 {
                    break;
                }
                let hint = HintNameItem::load(raw, off_name);
                let off2 = PE32::vaddr_to_off(&self.sect_hdr, hint.func_name_addr) as usize;
                if off2 == 0 {
                    off_name += HintNameItem::size();
                    off_addr += 4;
                    rva += 4;
                    continue;
                }
                let func_name = PE32::read_string(raw, off2 + 2);
                let real_addr = loader.resolve_api_name_in_module(&iim_name, &func_name);
                if real_addr == 0 {
                    break;
                }

                let patch_addr = base_addr as u64 + rva as u64;
                loader.write_dword(patch_addr, real_addr as u32);
                self.iat_names
                    .insert(real_addr as u32, format!("{}!{}", iim_name, func_name));

                off_name += HintNameItem::size();
                off_addr += 4;
                rva += 4;
            }
        }
    }

    /// Map a resolved import address back to its function name (O(1) lookup
    /// against the table built during binding — no file bytes needed).
    pub fn import_addr_to_name(&self, paddr: u32) -> String {
        self.iat_names
            .get(&paddr)
            .and_then(|s| s.split_once('!'))
            .map(|(_, name)| name.to_string())
            .unwrap_or_default()
    }
}
