mod common;
use std::{fs, path::Path};

#[test]
fn oversized_headers_are_rejected_by_verify_and_decrypt_without_output() {
    let directory = common::initialized_directory();
    let mut long_line = b"age-encryption.org/v1\n-> X25519 ".to_vec();
    long_line.extend(vec![b'A'; 128 * 1024]);
    long_line.push(b'\n');
    let mut many_stanzas = b"age-encryption.org/v1\n".to_vec();
    for _ in 0..5000 {
        many_stanzas.extend_from_slice(b"-> unknown recipient\nAA\n");
    }
    for bytes in [long_line, many_stanzas] {
        fs::write(directory.path().join("oversized.age"), bytes).unwrap();
        for result in [
            be::verify_in(directory.path(), Path::new("oversized.age")),
            be::decrypt_in(
                directory.path(),
                Path::new("oversized.age"),
                Path::new("output"),
            ),
        ] {
            let error = format!("{:#}", result.unwrap_err());
            assert!(error.contains("64 KiB"), "{error}");
        }
        assert!(!directory.path().join("output").exists());
        common::assert_no_temporary_files(directory.path());
    }
}

#[test]
fn hard_links_to_both_key_files_are_rejected_without_changing_keys() {
    let directory = common::initialized_directory();
    for key in [be::SECRET_KEY_FILE, be::PUBLIC_KEY_FILE] {
        let original = fs::read(directory.path().join(key)).unwrap();
        let alias = directory.path().join("alias");
        fs::hard_link(directory.path().join(key), &alias).unwrap();
        for result in [
            be::encrypt_in(directory.path(), Path::new("alias"), Path::new("output")),
            be::verify_in(directory.path(), Path::new("alias")),
            be::decrypt_in(directory.path(), Path::new("alias"), Path::new("output")),
        ] {
            assert!(format!("{:#}", result.unwrap_err()).contains("file aliases"));
        }
        assert_eq!(fs::read(directory.path().join(key)).unwrap(), original);
        assert!(!directory.path().join("output").exists());
        fs::remove_file(alias).unwrap();
    }
    common::assert_no_temporary_files(directory.path());
}

#[cfg(windows)]
#[test]
fn windows_aliases_and_device_names_are_rejected_as_inputs_and_outputs() {
    let directory = common::initialized_directory();
    fs::write(directory.path().join("plain"), b"test payload").unwrap();
    let original = fs::read(directory.path().join(be::SECRET_KEY_FILE)).unwrap();
    for name in [
        "key.key.",
        "key.key ",
        "key.key::$DATA",
        "key.pub.",
        "key.pub ",
        "key.pub::$DATA",
        "NUL",
        "COM1.txt",
        "LPT¹",
        "CON .txt",
    ] {
        for result in [
            be::encrypt_in(directory.path(), Path::new(name), Path::new("output")),
            be::encrypt_in(directory.path(), Path::new("plain"), Path::new(name)),
            be::verify_in(directory.path(), Path::new(name)),
            be::decrypt_in(directory.path(), Path::new(name), Path::new("output")),
        ] {
            assert!(
                format!("{:#}", result.unwrap_err()).contains("Windows"),
                "accepted {name}"
            );
        }
    }
    assert_eq!(
        fs::read(directory.path().join(be::SECRET_KEY_FILE)).unwrap(),
        original
    );
    assert!(!directory.path().join("output").exists());
    common::assert_no_temporary_files(directory.path());
}
