#![no_std]
#![no_main]

extern crate wdk_sys;

use wdk_sys::ntddk::*;
use wdk_sys::*;
use core::slice;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[global_allocator]
static ALLOCATOR: DummyAllocator = DummyAllocator;

struct DummyAllocator;

unsafe impl core::alloc::GlobalAlloc for DummyAllocator {
    unsafe fn alloc(&self, _layout: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}

macro_rules! wstr {
    ($s:expr) => {{
        const STR: &str = concat!($s, "\0");
        const LEN: usize = STR.len();
        const fn encode(s: &str) -> [u16; LEN] {
            let bytes = s.as_bytes();
            let mut result = [0u16; LEN];
            let mut i = 0;
            while i < LEN {
                result[i] = bytes[i] as u16;
                i += 1;
            }
            result
        }
        &encode(STR)
    }};
}

const DEVICE_NAME: &[u16] = wstr!("\\Device\\IoctlTest");
const SYMLINK_NAME: &[u16] = wstr!("\\DosDevices\\IoctlTest");

const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const IOCTL_SEND_STRING: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);

#[no_mangle]
pub extern "system" fn DriverEntry(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        DbgPrint(b"[driver] initializing ioctl driver...\n\0".as_ptr() as *const i8);

        let mut device_name = UNICODE_STRING {
            Length: ((DEVICE_NAME.len() - 1) * 2) as u16,
            MaximumLength: (DEVICE_NAME.len() * 2) as u16,
            Buffer: DEVICE_NAME.as_ptr() as *mut u16,
        };

        let mut device_object: PDEVICE_OBJECT = core::ptr::null_mut();

        let status = IoCreateDevice(
            driver_object,
            0,
            &mut device_name,
            FILE_DEVICE_UNKNOWN,
            0,
            0,
            &mut device_object,
        );

        if status != STATUS_SUCCESS {
            DbgPrint(b"[driver] error: device creation failed\n\0".as_ptr() as *const i8);
            return status;
        }

        DbgPrint(b"[driver] device created successfully\n\0".as_ptr() as *const i8);

        let mut symlink_name = UNICODE_STRING {
            Length: ((SYMLINK_NAME.len() - 1) * 2) as u16,
            MaximumLength: (SYMLINK_NAME.len() * 2) as u16,
            Buffer: SYMLINK_NAME.as_ptr() as *mut u16,
        };

        let symlink_status = IoCreateSymbolicLink(&mut symlink_name, &mut device_name);

        if symlink_status != STATUS_SUCCESS {
            DbgPrint(b"[driver] error: symlink creation failed\n\0".as_ptr() as *const i8);
            IoDeleteDevice(device_object);
            return symlink_status;
        }

        DbgPrint(b"[driver] symlink created\n\0".as_ptr() as *const i8);

        (*driver_object).MajorFunction[IRP_MJ_CREATE as usize] = Some(dispatch_create);
        (*driver_object).MajorFunction[IRP_MJ_CLOSE as usize] = Some(dispatch_close);
        (*driver_object).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(dispatch_ioctl);
        (*driver_object).DriverUnload = Some(driver_unload);

        DbgPrint(b"[driver] ready & loaded\n\0".as_ptr() as *const i8);

        STATUS_SUCCESS
    }
}

unsafe extern "C" fn dispatch_create(_device_object: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
    (*irp).IoStatus.Information = 0;
    IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
    STATUS_SUCCESS
}

unsafe extern "C" fn dispatch_close(_device_object: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
    (*irp).IoStatus.Information = 0;
    IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
    STATUS_SUCCESS
}

unsafe extern "C" fn dispatch_ioctl(_device_object: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    DbgPrint(b"[ioctl] recv request from usermode\n\0".as_ptr() as *const i8);
    
    let stack = (*irp).Tail.Overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation;
    let control_code = (*stack).Parameters.DeviceIoControl.IoControlCode;

    DbgPrint(b"[ioctl] code: 0x%X (expected: 0x%X)\n\0".as_ptr() as *const i8, control_code, IOCTL_SEND_STRING);

    let mut status = STATUS_SUCCESS;
    let mut info: usize = 0;

    if control_code == IOCTL_SEND_STRING {
        let input_buffer = (*irp).AssociatedIrp.SystemBuffer;
        let input_length = (*stack).Parameters.DeviceIoControl.InputBufferLength;

        if !input_buffer.is_null() && input_length > 0 {
            let data = slice::from_raw_parts(input_buffer as *const u8, input_length as usize);
            
            DbgPrint(b"[ioctl] msg from usermode: %s\n\0".as_ptr() as *const i8, data.as_ptr());
            DbgPrint(b"[ioctl] size: %d bytes\n\0".as_ptr() as *const i8, input_length);
            
            info = input_length as usize;
        } else {
            DbgPrint(b"[ioctl] error: invalid buffer/length\n\0".as_ptr() as *const i8);
        }
    } else {
        DbgPrint(b"[ioctl] error: unknown code 0x%X\n\0".as_ptr() as *const i8, control_code);
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    (*irp).IoStatus.__bindgen_anon_1.Status = status;
    (*irp).IoStatus.Information = info as u64;
    IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
    status
}

unsafe extern "C" fn driver_unload(driver_object: *mut DRIVER_OBJECT) {
    DbgPrint(b"[driver] unloading...\n\0".as_ptr() as *const i8);

    let mut symlink_name = UNICODE_STRING {
        Length: ((SYMLINK_NAME.len() - 1) * 2) as u16,
        MaximumLength: (SYMLINK_NAME.len() * 2) as u16,
        Buffer: SYMLINK_NAME.as_ptr() as *mut u16,
    };

    let _ = IoDeleteSymbolicLink(&mut symlink_name);
    IoDeleteDevice((*driver_object).DeviceObject);

    DbgPrint(b"[driver] unloaded successfully\n\0".as_ptr() as *const i8);
}

