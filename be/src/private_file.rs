//! Private creation on Unix and Windows. All other application code stays safe.
#![allow(unsafe_code)]
#[cfg(unix)]
use std::fs::OpenOptions;
use std::{fs::File, io, path::Path};

#[cfg(unix)]
pub(crate) fn create_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(windows)]
pub(crate) fn create_private(path: &Path) -> io::Result<File> {
    use std::{
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
        },
    };
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if wide_path[..wide_path.len() - 1].contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
    }
    // Protected DACL: only the object owner and SYSTEM. No inherited group access.
    // The descriptor is supplied at creation, before even an empty file is visible.
    let sddl: Vec<u16> = "D:P(A;;FA;;;SY)(A;;FA;;;OW)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: both strings are NUL-terminated, the output pointer is valid, and the
    // descriptor is released with LocalFree after CreateFileW has copied it.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .expect("SECURITY_ATTRIBUTES size fits in u32"),
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: all pointers refer to live, correctly initialized values. CREATE_NEW
    // cannot follow or overwrite an existing path. The returned handle is owned.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    let error = io::Error::last_os_error();
    // SAFETY: this allocation came from the conversion API and is freed exactly once.
    unsafe {
        LocalFree(descriptor);
    }
    if handle == INVALID_HANDLE_VALUE {
        Err(error)
    } else {
        // SAFETY: CreateFileW returned a valid, unique owned file handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("private output requires Unix or Windows file permissions");

#[cfg(all(test, windows))]
pub(crate) fn assert_private(file: &File) {
    use std::{os::windows::io::AsRawHandle, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
                SE_FILE_OBJECT,
            },
            DACL_SECURITY_INFORMATION,
        },
    };
    let mut descriptor = ptr::null_mut();
    // SAFETY: the file handle is live; the descriptor out-pointer is valid.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    assert_eq!(status, 0, "read file DACL");
    let mut encoded = ptr::null_mut();
    let mut length = 0;
    // SAFETY: the descriptor came from GetSecurityInfo; both outputs are valid.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            DACL_SECURITY_INFORMATION,
            &raw mut encoded,
            &raw mut length,
        )
    };
    let text = if converted != 0 {
        // SAFETY: the API returns an initialized UTF-16 buffer of length code units.
        let units =
            unsafe { std::slice::from_raw_parts(encoded, usize::try_from(length).unwrap()) };
        String::from_utf16_lossy(units)
            .trim_end_matches('\0')
            .to_owned()
    } else {
        String::new()
    };
    // SAFETY: these allocations came from the security APIs and are freed once.
    unsafe {
        if !encoded.is_null() {
            LocalFree(encoded.cast());
        }
        LocalFree(descriptor);
    }
    assert_ne!(converted, 0, "convert DACL to SDDL");
    assert_eq!(
        text, "D:P(A;;FA;;;SY)(A;;FA;;;OW)",
        "file must allow only SYSTEM and owner, without inheritance"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_creation_never_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing");
        std::fs::write(&path, b"preserve").unwrap();
        assert_eq!(
            create_private(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(path).unwrap(), b"preserve");
    }

    #[cfg(windows)]
    #[test]
    fn private_file_excludes_inherited_access_before_writes_and_after_publish() {
        let dir = tempfile::tempdir().unwrap();
        let temporary = tempfile::Builder::new()
            .make_in(dir.path(), create_private)
            .unwrap();
        assert_private(temporary.as_file());
        let output = temporary
            .persist_noclobber(dir.path().join("published"))
            .unwrap();
        assert_private(&output);
    }

    #[cfg(unix)]
    #[test]
    fn private_file_has_no_group_or_other_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = create_private(&dir.path().join("private")).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o077, 0);
    }
}
