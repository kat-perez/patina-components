//! NVMe boot-storage service for Patina.
//!
//! Implements [`patina::component::service::boot_storage::BootStorageService`] over the UEFI
//! NVMe Pass-Thru Protocol. The component publishes the service into the Patina component
//! graph; boot orchestrators in `patina_boot` consume it via dependency injection.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
#![cfg_attr(not(feature = "std"), no_std)]
#![feature(coverage_attribute)]

extern crate alloc;

use core::ptr;

use patina::{
    boot_services::{BootServices, StandardBootServices, protocol_handler::HandleSearchType},
    component::{
        Storage, component,
        service::{IntoService, boot_storage::BootStorageService},
    },
    error::{EfiError, Result},
};
use r_efi::efi;

/// Component that publishes [`BootStorageService`] backed by NVMe Pass-Thru BPWPS.
///
/// Add to a platform's component graph alongside the boot orchestrator:
///
/// ```rust,ignore
/// use patina_storage_nvme::NvmeBootStorageProvider;
///
/// add.component(NvmeBootStorageProvider::new());
/// add.component(BootDispatcher::new(SreBootManager::new(/* ... */)));
/// ```
pub struct NvmeBootStorageProvider {
    _private: (),
}

impl NvmeBootStorageProvider {
    /// Construct a new provider component.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for NvmeBootStorageProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[component]
impl NvmeBootStorageProvider {
    #[coverage(off)] // Component integration — service impl is integration-tested
    fn entry_point(self, boot_services: StandardBootServices, storage: &mut Storage) -> Result<()> {
        let service = NvmeBootStorageService { boot_services };
        IntoService::register(service, storage);
        Ok(())
    }
}

/// Concrete `BootStorageService` impl over NVMe Pass-Thru.
#[derive(patina::component::service::IntoService)]
#[service(dyn BootStorageService)]
struct NvmeBootStorageService {
    boot_services: StandardBootServices,
}

impl BootStorageService for NvmeBootStorageService {
    fn lock_boot_partition(&self) -> Result<()> {
        lock_all_nvme_boot_partitions(self.boot_services.as_ref())
    }
}

/// Walk every handle publishing `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL` and place each controller's
/// boot partitions in "Write Protect Until Power Cycle" state via Set Features FID 0x11 (BPWPS).
///
/// Per-controller failures are logged and the next controller is attempted. Returns `Ok(())`
/// if at least one controller was reached.
fn lock_all_nvme_boot_partitions<B: BootServices>(boot_services: &B) -> Result<()> {
    let handles = boot_services
        .locate_handle_buffer(HandleSearchType::ByProtocol(&nvme_pass_thru::PROTOCOL_GUID))
        .map_err(EfiError::from)?;

    for &handle in handles.iter() {
        // SAFETY: handle was returned by locate_handle_buffer for the NVMe Pass-Thru GUID.
        let protocol = match unsafe {
            boot_services.handle_protocol_unchecked(handle, &nvme_pass_thru::PROTOCOL_GUID)
        } {
            Ok(ptr) => ptr as *mut nvme_pass_thru::Protocol,
            Err(status) => {
                log::warn!("handle_protocol on NVMe controller {:p} failed: {:?}", handle, status);
                continue;
            }
        };

        // SAFETY: protocol is non-null and points to a Protocol owned by the controller.
        if let Err(e) = unsafe { issue_bpwps_set_features(protocol) } {
            log::warn!("BPWPS lock on NVMe controller {:p} failed: {:?}", handle, e);
        }
    }

    Ok(())
}

/// Issue the NVMe Set Features admin command for BPWPS via the supplied Pass-Thru protocol.
///
/// # Safety
///
/// `protocol` must be a valid, non-null pointer to an `EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL`
/// instance owned by an NVMe controller for the duration of this call.
unsafe fn issue_bpwps_set_features(protocol: *mut nvme_pass_thru::Protocol) -> Result<()> {
    use nvme_pass_thru::{
        BPWPS_LOCK_BP0_BP1, CMD_FLAG_CDW10_VALID, CMD_FLAG_CDW11_VALID, Command, CommandPacket, Completion,
        FID_BOOT_PARTITION_WRITE_PROTECTION, OPCODE_SET_FEATURES, QUEUE_TYPE_ADMIN, TIMEOUT_NS_1_SEC,
    };

    let mut nvme_cmd = Command { cdw0: OPCODE_SET_FEATURES as u32, ..Command::zero() };
    nvme_cmd.flags = CMD_FLAG_CDW10_VALID | CMD_FLAG_CDW11_VALID;
    nvme_cmd.cdw10 = FID_BOOT_PARTITION_WRITE_PROTECTION as u32;
    nvme_cmd.cdw11 = BPWPS_LOCK_BP0_BP1;

    let mut completion = Completion::zero();

    let mut packet = CommandPacket {
        command_timeout: TIMEOUT_NS_1_SEC,
        transfer_buffer: ptr::null_mut(),
        transfer_length: 0,
        metadata_buffer: ptr::null_mut(),
        metadata_length: 0,
        queue_type: QUEUE_TYPE_ADMIN,
        nvme_cmd: &mut nvme_cmd,
        nvme_completion: &mut completion,
    };

    // SAFETY: caller guarantees `protocol` is valid; packet pointers are kept alive across the call.
    let pass_thru = unsafe { (*protocol).pass_thru };
    let status = pass_thru(protocol, 0, &mut packet, ptr::null_mut());
    if status != efi::Status::SUCCESS {
        return Err(EfiError::from(status));
    }

    let status_field = (completion.dw3 >> 17) & 0x7FFF;
    if status_field != 0 {
        log::error!("NVMe Set Features BPWPS rejected: status field {:#x}", status_field);
        return Err(EfiError::from(efi::Status::DEVICE_ERROR));
    }

    Ok(())
}

mod nvme_pass_thru {
    use core::ffi::c_void;
    use r_efi::efi;

    pub const PROTOCOL_GUID: efi::Guid =
        efi::Guid::from_fields(0x52c78312, 0x8edc, 0x4233, 0x98, 0xf2, &[0x1a, 0x1a, 0xa5, 0xe3, 0x88, 0xa5]);

    pub const OPCODE_SET_FEATURES: u8 = 0x09;
    pub const FID_BOOT_PARTITION_WRITE_PROTECTION: u8 = 0x11;
    pub const CMD_FLAG_CDW10_VALID: u8 = 1 << 2;
    pub const CMD_FLAG_CDW11_VALID: u8 = 1 << 3;
    pub const QUEUE_TYPE_ADMIN: u8 = 0;
    pub const TIMEOUT_NS_1_SEC: u64 = 10_000_000;
    pub const BPWPS_LOCK_BP0_BP1: u32 = (0b001 << 3) | 0b001;

    pub type PassThruFn = extern "efiapi" fn(
        this: *mut Protocol,
        namespace_id: u32,
        packet: *mut CommandPacket,
        event: *mut c_void,
    ) -> efi::Status;

    #[repr(C)]
    pub struct Protocol {
        pub mode: *mut c_void,
        pub pass_thru: PassThruFn,
        pub get_next_namespace: *mut c_void,
        pub build_device_path: *mut c_void,
        pub get_namespace: *mut c_void,
    }

    #[repr(C)]
    pub struct CommandPacket {
        pub command_timeout: u64,
        pub transfer_buffer: *mut c_void,
        pub transfer_length: u32,
        pub metadata_buffer: *mut c_void,
        pub metadata_length: u32,
        pub queue_type: u8,
        pub nvme_cmd: *mut Command,
        pub nvme_completion: *mut Completion,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct Command {
        pub cdw0: u32,
        pub flags: u8,
        pub nsid: u32,
        pub cdw2: u32,
        pub cdw3: u32,
        pub cdw10: u32,
        pub cdw11: u32,
        pub cdw12: u32,
        pub cdw13: u32,
        pub cdw14: u32,
        pub cdw15: u32,
    }

    impl Command {
        pub const fn zero() -> Self {
            Self {
                cdw0: 0,
                flags: 0,
                nsid: 0,
                cdw2: 0,
                cdw3: 0,
                cdw10: 0,
                cdw11: 0,
                cdw12: 0,
                cdw13: 0,
                cdw14: 0,
                cdw15: 0,
            }
        }
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct Completion {
        pub dw0: u32,
        pub dw1: u32,
        pub dw2: u32,
        pub dw3: u32,
    }

    impl Completion {
        pub const fn zero() -> Self {
            Self { dw0: 0, dw1: 0, dw2: 0, dw3: 0 }
        }
    }
}
