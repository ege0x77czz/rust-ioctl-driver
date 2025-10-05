type HANDLE = isize;
type BOOL = i32;
type DWORD = u32;
type LPCWSTR = *const u16;
type LPSECURITY_ATTRIBUTES = *const core::ffi::c_void;
type LPOVERLAPPED = *const core::ffi::c_void;

const INVALID_HANDLE_VALUE: HANDLE = -1;
const GENERIC_READ: DWORD = 0x80000000;
const GENERIC_WRITE: DWORD = 0x40000000;
const OPEN_EXISTING: DWORD = 3;
const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;
const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const IOCTL_SEND_STRING: u32 = ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);

extern "system" {
    fn CreateFileW(
        lpFileName: LPCWSTR,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE,
    ) -> HANDLE;

    fn DeviceIoControl(
        hDevice: HANDLE,
        dwIoControlCode: DWORD,
        lpInBuffer: *const core::ffi::c_void,
        nInBufferSize: DWORD,
        lpOutBuffer: *mut core::ffi::c_void,
        nOutBufferSize: DWORD,
        lpBytesReturned: *mut DWORD,
        lpOverlapped: LPOVERLAPPED,
    ) -> BOOL;

    fn CloseHandle(hObject: HANDLE) -> BOOL;
    
    fn GetLastError() -> DWORD;
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let message_str = if args.len() > 1 {
        &args[1]
    } else {
        "can't stop thinking of you"
    };

    unsafe {
        let device_path: Vec<u16> = "\\\\.\\IoctlTest\0"
            .encode_utf16()
            .collect();

        let handle = CreateFileW(
            device_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            core::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );

        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            println!("[client] error: couldn't open device");
            return;
        }

        println!("[client] device opened successfully");

        let mut message = message_str.to_string();
        message.push('\0');
        let message_bytes = message.as_bytes();
        let mut bytes_returned: u32 = 0;

        println!("[client] sending msg to kernel: '{}'", message_str);

        let result = DeviceIoControl(
            handle,
            IOCTL_SEND_STRING,
            message_bytes.as_ptr() as *const _,
            message_bytes.len() as u32,
            core::ptr::null_mut(),
            0,
            &mut bytes_returned,
            core::ptr::null_mut(),
        );

        if result != 0 {
            println!("[client] success! msg sent to kernel");
            println!("[client] bytes returned: {}", bytes_returned);
        } else {
            let error = GetLastError();
            println!("[client] error: ioctl failed (code: {})", error);
        }

        CloseHandle(handle);
    }
}

