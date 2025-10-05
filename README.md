# Rust IOCTL Driver

minimal windows kernel driver written in rust for usermode-kernel communication via ioctl

## what is this

simple example showing how to send messages from usermode app to kernel driver using ioctl mechanism. usermode client sends a string, kernel driver receives it and prints it via dbgprint.

```
usermode app  -->  IOCTL  -->  kernel driver  -->  debug output
```

## structure

```
driver/  - kernel driver (no_std rust)
client/  - usermode client app
```

## build

```powershell
cd driver && cargo build --release
copy target\x86_64-pc-windows-msvc\release\ioctl_driver.dll target\x86_64-pc-windows-msvc\release\ioctl_driver.sys
cd ../client && cargo build --release
```

## setup

**1. enable test signing** (disable secure boot in bios first)
```powershell
bcdedit /set testsigning on
```
reboot

**2. create & sign driver**
```powershell
New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=TestDriverCert" -CertStoreLocation Cert:\CurrentUser\My
$cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object {$_.Subject -eq "CN=TestDriverCert"} | Select-Object -First 1
Export-Certificate -Cert $cert -FilePath TestDriverCert.cer
Import-Certificate -FilePath TestDriverCert.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath TestDriverCert.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
Set-AuthenticodeSignature -FilePath "target\x86_64-pc-windows-msvc\release\ioctl_driver.sys" -Certificate $cert
```

**3. load driver**
```powershell
sc create IoctlDriver binPath= "C:\full\path\to\ioctl_driver.sys" type= kernel start= demand
sc start IoctlDriver
```

**4. run client**
```powershell
cd client
cargo run --release
cargo run --release "custom message"
```

## output

use [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview) (run as admin, enable capture kernel)

**client:**
```
[client] device opened successfully
[client] sending msg to kernel: 'i watch the moon'
[client] success! msg sent to kernel
```

**kernel:**
```
[driver] initializing ioctl driver...
[driver] ready & loaded
[ioctl] recv request from usermode
[ioctl] msg from usermode: i watch the moon
```

## tech

- **ioctl code:** `0x222000` (CTL_CODE macro)
- **device:** `\Device\IoctlTest` → `\DosDevices\IoctlTest`
- **method:** METHOD_BUFFERED
- **deps:** wdk-sys for kernel bindings

## cleanup

```powershell
sc stop IoctlDriver
sc delete IoctlDriver
bcdedit /set testsigning off
```

## license

MIT

