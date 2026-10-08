//! UI language only. Authentication and OpenSSH subprocesses retain their
//! sanitized C locale; neither caller environment nor API values select it.
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const MAX_CONFIG_BYTES: u64 = 16 * 1024;

/// Read afresh so a system language change reaches the next metadata refresh
/// and the next protected window without restarting the helper.
pub fn system_ui_language() -> &'static str {
    read_language(Path::new("/etc/locale.conf"), 0).unwrap_or("en")
}

fn read_language(path: &Path, expected_uid: u32) -> Option<&'static str> {
    // O_NONBLOCK prevents a substituted FIFO from stalling the service;
    // O_NOFOLLOW rejects a substituted final symlink. Only a trusted regular
    // file may reach the bounded read below, and no shell parses its contents.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let before = file.metadata().ok()?;
    if !before.is_file()
        || before.uid() != expected_uid
        || before.mode() & 0o022 != 0
        || before.len() > MAX_CONFIG_BYTES
    {
        return None;
    }
    let mut contents = Vec::new();
    (&file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut contents)
        .ok()?;
    let after = file.metadata().ok()?;
    if contents.len() as u64 > MAX_CONFIG_BYTES
        || before.uid() != after.uid()
        || before.mode() != after.mode()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return None;
    }
    parse_language(std::str::from_utf8(&contents).ok()?)
}

fn parse_language(contents: &str) -> Option<&'static str> {
    let mut lang = "";
    let mut messages = "";
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once('=')?;
        let name = name.trim();
        if name.is_empty()
            || !name.bytes().enumerate().all(|(i, byte)| {
                byte.is_ascii_alphabetic() || byte == b'_' || (i > 0 && byte.is_ascii_digit())
            })
        {
            return None;
        }
        let value = assignment_value(value)?;
        match name {
            "LANG" => lang = value,
            "LC_MESSAGES" => messages = value,
            // LC_ALL is not valid in locale.conf. LANGUAGE is gettext's
            // preference list; the UI follows the system message locale.
            _ => (),
        }
    }
    let locale = if messages.is_empty() { lang } else { messages };
    if locale.len() > 128
        || !locale
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@'))
    {
        return None;
    }
    // Match the language subtag, never prefixes such as "russian" or "rug".
    let language = locale.split(['_', '-', '.', '@']).next().unwrap_or("");
    Some(if language.eq_ignore_ascii_case("ru") {
        "ru"
    } else {
        "en"
    })
}

fn assignment_value(value: &str) -> Option<&str> {
    let value = value.trim();
    if let Some(quote) = value.chars().next().filter(|c| matches!(c, '\'' | '"')) {
        let end = value[1..].find(quote)? + 1;
        let tail = &value[end + 1..];
        if !tail.is_empty()
            && !(tail.starts_with(char::is_whitespace)
                && (tail.trim().is_empty() || tail.trim_start().starts_with('#')))
        {
            return None;
        }
        let result = &value[1..end];
        // Locale identifiers need no expansion or escaping. Reject shell
        // constructs instead of guessing at their meaning.
        return (!result.contains(['$', '`', '\\', '\0'])).then_some(result);
    }
    let end = value.find(char::is_whitespace).unwrap_or(value.len());
    let tail = value[end..].trim_start();
    if !tail.is_empty() && !tail.starts_with('#') {
        return None;
    }
    let result = &value[..end];
    (!result.contains(['\'', '"', '$', '`', '\\', '\0', '#'])).then_some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::CString,
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        time::Instant,
    };

    #[test]
    fn system_message_locale_takes_precedence_over_language() {
        for (config, expected) in [
            ("LANG=ru_RU.UTF-8\n", "ru"),
            ("LANG=en_US.UTF-8\nLC_MESSAGES=ru_RU.UTF-8\n", "ru"),
            ("LC_MESSAGES=en_GB.UTF-8\nLANG=ru_RU.UTF-8\n", "en"),
            ("LANG=ru_RU.UTF-8\nLC_MESSAGES=\n", "ru"),
            ("LANG=ru_RU.UTF-8\nLC_MESSAGES=\"\"\n", "ru"),
            ("LANG=ru\nLANG=en_US.UTF-8\n", "en"),
            ("LANG=en\nLC_MESSAGES=ru_RU\nLC_MESSAGES=en_GB\n", "en"),
            (
                "LANG=en_US.UTF-8\nLANGUAGE=ru:en\nLC_ALL=ru_RU.UTF-8\n",
                "en",
            ),
        ] {
            assert_eq!(parse_language(config), Some(expected), "{config:?}");
        }
    }

    #[test]
    fn comments_quotes_whitespace_and_locale_variants_are_supported() {
        for config in [
            "# System locale\n\nLANG=ru_RU.UTF-8\n",
            "  LANG = \"ru_RU.UTF-8\"  # chosen system language\r\n",
            "LANG='ru_RU.UTF-8'\nLC_TIME=en_US.UTF-8\n",
            "LANG=ru_RU.UTF-8 # system language\n",
            "LANG=ru\n",
            "LANG=RU_ru.utf8@variant\n",
            "LANG=ru-RU\n",
        ] {
            assert_eq!(parse_language(config), Some("ru"), "{config:?}");
        }
    }

    #[test]
    fn unsupported_or_unset_locales_fall_back_to_english() {
        for config in [
            "",
            "# no language\n",
            "LANG=\n",
            "LANG=C\n",
            "LANG=C.UTF-8\n",
            "LANG=POSIX\n",
            "LANG=de_DE.UTF-8\n",
            "LANG=rug\n",
            "LANG=russian\n",
            "LANG=ru_RU.UTF-8\nLC_MESSAGES=C.UTF-8\n",
        ] {
            assert_eq!(parse_language(config), Some("en"), "{config:?}");
        }
    }

    #[test]
    fn malformed_assignments_and_shell_expressions_are_not_interpreted() {
        for config in [
            "LANG=\"ru_RU.UTF-8\n",
            "LANG='ru_RU.UTF-8\n",
            "LANG=ru_RU.UTF-8 junk\n",
            "LANG=\"ru\"_RU.UTF-8\n",
            "LANG=\"ru\"#comment\n",
            "LANG=ru#comment\n",
            "LANG=$(printf ru)\n",
            "LANG='${OTHER}'\n",
            "LANG=`id`\n",
            "LANG=ru\\_RU\n",
            "export LANG=ru\n",
            "LANG=ru\ninvalid line\n",
            "LANG=ru\0\n",
            "1LANG=ru\n",
        ] {
            assert_eq!(parse_language(config), None, "{config:?}");
        }
        assert_eq!(parse_language(&format!("LANG={}\n", "r".repeat(129))), None);
    }

    #[test]
    fn trusted_regular_file_is_reread_without_caching() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("locale.conf");
        let uid = unsafe { libc::geteuid() };
        fs::write(&path, "LANG=ru_RU.UTF-8\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_language(&path, uid), Some("ru"));
        fs::write(&path, "LANG=en_US.UTF-8\n").unwrap();
        assert_eq!(read_language(&path, uid), Some("en"));
        assert_eq!(read_language(&path, uid.wrapping_add(1)), None);
        fs::remove_file(&path).unwrap();
        assert_eq!(read_language(&path, uid), None);
    }

    #[test]
    fn unsafe_files_symlinks_directories_and_oversized_input_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("locale.conf");
        let link = directory.path().join("link");
        let uid = unsafe { libc::geteuid() };
        fs::write(&path, "LANG=ru\n").unwrap();
        for mode in [0o666, 0o664, 0o646] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(read_language(&path, uid), None);
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&path, &link).unwrap();
        assert_eq!(read_language(&link, uid), None);
        assert_eq!(read_language(directory.path(), uid), None);
        fs::write(&path, [0xff]).unwrap();
        assert_eq!(read_language(&path, uid), None);
        fs::write(&path, " ".repeat(MAX_CONFIG_BYTES as usize + 1)).unwrap();
        assert_eq!(read_language(&path, uid), None);
    }

    #[test]
    fn fifo_does_not_block_locale_reader() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("locale.conf");
        let name = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        assert_eq!(read_language(&path, unsafe { libc::geteuid() }), None);
        assert!(start.elapsed().as_secs() < 1);
    }
}
