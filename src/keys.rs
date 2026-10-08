use crate::{Error, Result, process};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const MAX_KEY: u64 = 1024 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Key {
    pub id: String,
    pub path: PathBuf,
    pub name: String,
    pub fingerprint: String,
    pub algorithm: String,
    pub encrypted: bool,
    pub public_blob: String,
    pub unavailable: Option<String>,
    #[serde(default)]
    pub unencrypted_copies: Vec<PathBuf>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    pub encrypted: bool,
    pub algorithm: String,
    pub public_blob: String,
    pub fingerprint: String,
}
pub fn field<'a>(b: &mut &'a [u8]) -> Result<&'a [u8]> {
    if b.len() < 4 {
        return Err(Error("invalid_key"));
    }
    let n = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
    if n > b.len() - 4 {
        return Err(Error("invalid_key"));
    }
    let r = &b[4..4 + n];
    *b = &b[4 + n..];
    Ok(r)
}
pub fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}
pub fn parse(data: &[u8]) -> Result<Header> {
    let text = std::str::from_utf8(data).map_err(|_| Error("unsupported_format"))?;
    let body = text
        .strip_prefix("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        .and_then(|s| s.split_once("-----END OPENSSH PRIVATE KEY-----"))
        .ok_or(Error("unsupported_format"))?;
    if !body.1.trim().is_empty() {
        return Err(Error("invalid_key"));
    }
    let compact = Zeroizing::new(body.0.split_whitespace().collect::<String>());
    let raw = Zeroizing::new(
        STANDARD
            .decode(compact.as_bytes())
            .map_err(|_| Error("invalid_key"))?,
    );
    let mut b = raw
        .strip_prefix(b"openssh-key-v1\0")
        .ok_or(Error("invalid_key"))?;
    let cipher = field(&mut b)?;
    let kdf = field(&mut b)?;
    let options = field(&mut b)?;
    let encrypted = cipher != b"none";
    if (encrypted && (kdf != b"bcrypt" || options.is_empty()))
        || (!encrypted && (kdf != b"none" || !options.is_empty()))
    {
        return Err(Error("unsupported_cipher"));
    }
    if encrypted
        && ![
            b"aes256-ctr".as_slice(),
            b"aes256-cbc",
            b"aes192-ctr",
            b"aes128-ctr",
            b"aes128-cbc",
            b"aes192-cbc",
            b"aes128-gcm@openssh.com",
            b"aes256-gcm@openssh.com",
            b"chacha20-poly1305@openssh.com",
        ]
        .contains(&cipher)
    {
        return Err(Error("unsupported_cipher"));
    }
    if b.len() < 4 || b[..4] != [0, 0, 0, 1] {
        return Err(Error("unsupported_key_count"));
    }
    b = &b[4..];
    let public = field(&mut b)?;
    let private = field(&mut b)?;
    if private.is_empty() {
        return Err(Error("invalid_key"));
    }
    let mut p = public;
    let algorithm = std::str::from_utf8(field(&mut p)?)
        .map_err(|_| Error("invalid_key"))?
        .to_owned();
    if ![
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ]
    .contains(&algorithm.as_str())
    {
        return Err(Error("unsupported_algorithm"));
    }
    match algorithm.as_str() {
        "ssh-ed25519" => {
            if field(&mut p)?.len() != 32 {
                return Err(Error("invalid_key"));
            }
        }
        "ssh-rsa" => {
            let e = field(&mut p)?;
            let n = field(&mut p)?;
            if e.is_empty() || e.len() > 8 || n.len() < 128 || n.len() > 2049 {
                return Err(Error("unsupported_rsa_size"));
            }
        }
        _ => {
            let curve = field(&mut p)?;
            let point = field(&mut p)?;
            let (name, size) = match algorithm.as_str() {
                "ecdsa-sha2-nistp256" => (b"nistp256".as_slice(), 65),
                "ecdsa-sha2-nistp384" => (b"nistp384".as_slice(), 97),
                _ => (b"nistp521".as_slice(), 133),
            };
            if curve != name || point.len() != size {
                return Err(Error("invalid_key"));
            }
        }
    }
    if !p.is_empty() {
        return Err(Error("invalid_key"));
    }
    Ok(Header {
        encrypted,
        algorithm,
        public_blob: STANDARD.encode(public),
        fingerprint: fingerprint(public),
    })
}
fn stat_id(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64, u32, u64) {
    (
        m.dev(),
        m.ino(),
        m.size(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.mode(),
        m.nlink(),
    )
}
pub struct Snapshot {
    pub canonical: PathBuf,
    path: PathBuf,
    root: PathBuf,
    original: File,
    metadata: fs::Metadata,
    pub memory: File,
    pub header: Header,
    digest: Vec<u8>,
}
impl Snapshot {
    pub fn open(root: &Path, path: &Path, uid: u32, modify: bool) -> Result<Self> {
        let root = root.canonicalize()?;
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&root) {
            return Err(Error("outside_ssh_directory"));
        }
        // Validate every resolved parent. No group/world-writable path can be
        // used as the replacement directory, even if the final file is private.
        let mut parent = canonical.parent();
        while let Some(p) = parent {
            let m = fs::symlink_metadata(p)?;
            if !m.is_dir() || (m.uid() != uid && m.uid() != 0) || m.mode() & 0o022 != 0 {
                return Err(Error("unsafe_directory"));
            }
            if p == root {
                break;
            }
            parent = p.parent();
        }
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&canonical)?;
        let m = f.metadata()?;
        if !m.is_file() || m.uid() != uid || m.size() > MAX_KEY || m.mode() & 0o077 != 0 {
            return Err(Error("unsafe_key_file"));
        }
        if modify && m.nlink() != 1 {
            return Err(Error("multiple_hard_links"));
        }
        let mut data = Zeroizing::new(Vec::new());
        (&mut f).take(MAX_KEY + 1).read_to_end(&mut data)?;
        if stat_id(&m) != stat_id(&f.metadata()?) || data.len() as u64 != m.size() {
            return Err(Error("file_conflict"));
        }
        let header = parse(&data)?;
        let memory = process::memfile(&data, true)?;
        let digest = Sha256::digest(&data).to_vec();
        Ok(Self {
            canonical,
            path: path.into(),
            root,
            original: f,
            metadata: m,
            memory,
            header,
            digest,
        })
    }
    pub fn unchanged(&mut self) -> Result<()> {
        if self.path.canonicalize()? != self.canonical || !self.canonical.starts_with(&self.root) {
            return Err(Error("file_conflict"));
        }
        let m = fs::symlink_metadata(&self.canonical)?;
        if stat_id(&m) != stat_id(&self.metadata)
            || stat_id(&self.original.metadata()?) != stat_id(&self.metadata)
        {
            return Err(Error("file_conflict"));
        }
        self.original.seek(SeekFrom::Start(0))?;
        let mut data = Zeroizing::new(Vec::new());
        (&mut self.original)
            .take(MAX_KEY + 1)
            .read_to_end(&mut data)?;
        if Sha256::digest(&data).as_slice() != self.digest {
            return Err(Error("file_conflict"));
        }
        Ok(())
    }
    pub fn verify(&self, pass: &[u8]) -> Result<()> {
        let out = process::key_command(&["-y"], &self.memory, pass, true)?;
        let public = std::str::from_utf8(&out)
            .map_err(|_| Error("invalid_key"))?
            .split_whitespace()
            .nth(1)
            .ok_or(Error("invalid_key"))?;
        if public != self.header.public_blob {
            return Err(Error("fingerprint_mismatch"));
        }
        Ok(())
    }
    pub fn encrypted_copy(&self, pass: &[u8]) -> Result<Vec<u8>> {
        if self.header.encrypted {
            return Err(Error("already_encrypted"));
        }
        if pass.is_empty() {
            return Err(Error("empty_passphrase"));
        }
        self.verify(b"")?;
        let mut input = self.memory.try_clone()?;
        input.seek(SeekFrom::Start(0))?;
        let mut original = Zeroizing::new(Vec::new());
        input.read_to_end(&mut original)?;
        let mut output = process::memfile(&original, false)?;
        process::key_command(&["-p", "-a", "64"], &output, pass, false)?;
        output.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        (&mut output).take(MAX_KEY + 1).read_to_end(&mut bytes)?;
        let h = parse(&bytes)?;
        if !h.encrypted || h.fingerprint != self.header.fingerprint {
            return Err(Error("fingerprint_mismatch"));
        }
        let out = process::key_command(&["-y"], &output, pass, true)?;
        if std::str::from_utf8(&out)
            .map_err(|_| Error("invalid_key"))?
            .split_whitespace()
            .nth(1)
            != Some(&h.public_blob)
        {
            return Err(Error("fingerprint_mismatch"));
        }
        Ok(bytes)
    }
    pub fn replace(&mut self, encrypted: &[u8]) -> Result<()> {
        let h = parse(encrypted)?;
        if !h.encrypted || h.fingerprint != self.header.fingerprint {
            return Err(Error("invalid_replacement"));
        }
        self.unchanged()?;
        let parent = self
            .canonical
            .parent()
            .ok_or(Error("invalid_path"))?
            .to_path_buf();
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&parent)?;
        let leaf = CString::new(self.canonical.file_name().unwrap().as_bytes())
            .map_err(|_| Error("invalid_path"))?;
        let name =
            CString::new(format!(".ssh-keys-{}.enc", crate::platform::random_id()?)).unwrap();
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(Error("write_failed"));
        }
        use std::os::fd::FromRawFd;
        let mut temp = unsafe { File::from_raw_fd(fd) };
        let before = (|| -> Result<()> {
            temp.write_all(encrypted)?;
            temp.sync_all()?;
            self.unchanged()?;
            let current_dir = fs::metadata(&parent)?;
            let held_dir = dir.metadata()?;
            if (current_dir.dev(), current_dir.ino()) != (held_dir.dev(), held_dir.ino()) {
                return Err(Error("file_conflict"));
            }
            if unsafe {
                libc::renameat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    dir.as_raw_fd(),
                    leaf.as_ptr(),
                )
            } != 0
            {
                return Err(Error("write_failed"));
            }
            Ok(())
        })();
        if before.is_err() {
            unsafe {
                libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
            }
            return before;
        }
        // After rename we NEVER restore the plaintext. Report durability failure.
        dir.sync_all().map_err(|_| Error("partial_commit"))?;
        Ok(())
    }
}
pub fn scan(root: &Path, uid: u32) -> Result<Vec<Key>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) -> Result<()> {
        if depth > 32 || out.len() > 4096 {
            return Err(Error("scan_limit"));
        }
        for entry in fs::read_dir(dir)? {
            if out.len() >= 4096 {
                return Err(Error("scan_limit"));
            }
            let e = entry?;
            let t = e.file_type()?;
            if t.is_dir() {
                walk(&e.path(), out, depth + 1)?;
            } else if t.is_file() || t.is_symlink() {
                out.push(e.path());
            }
        }
        Ok(())
    }
    walk(root, &mut paths, 0)?;
    paths.sort();
    let mut keys = Vec::new();
    let mut seen = BTreeSet::new();
    for path in paths {
        if keys.len() >= 512 {
            return Err(Error("scan_limit"));
        }
        if path.extension().is_some_and(|e| e == "pub") {
            continue;
        }
        let Ok(m) = fs::metadata(&path) else { continue };
        if !m.is_file() || m.size() > MAX_KEY {
            continue;
        }
        if !path.canonicalize()?.starts_with(root.canonicalize()?) {
            keys.push(Key {
                id: format!(
                    "unavailable:{}",
                    STANDARD_NO_PAD.encode(Sha256::digest(path.as_os_str().as_bytes()))
                ),
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                path,
                fingerprint: String::new(),
                algorithm: "unknown".into(),
                encrypted: false,
                public_blob: String::new(),
                unavailable: Some("outside_ssh_directory".into()),
                unencrypted_copies: Vec::new(),
            });
            continue;
        }
        // No duplicate rows for a symlink and its actual target. Separate files
        // with the same public key remain visible as unencrypted copies.
        if !seen.insert((m.dev(), m.ino())) {
            continue;
        }
        let mut f = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut data = Zeroizing::new(Vec::new());
        (&mut f).take(MAX_KEY + 1).read_to_end(&mut data)?;
        if !data.starts_with(b"-----BEGIN ") || !data.windows(11).any(|w| w == b"PRIVATE KEY") {
            continue;
        }
        let result = parse(&data);
        let (header, mut unavailable) = match result {
            Ok(h) => (h, None),
            Err(e) => (
                Header {
                    encrypted: false,
                    algorithm: "unknown".into(),
                    public_blob: String::new(),
                    fingerprint: String::new(),
                },
                Some(e.0.to_owned()),
            ),
        };
        if unavailable.is_none()
            && let Err(e) = Snapshot::open(root, &path, uid, !header.encrypted)
        {
            unavailable = Some(e.0.into());
        }
        let id = if header.fingerprint.is_empty() {
            format!(
                "unsupported:{}",
                STANDARD_NO_PAD.encode(Sha256::digest(path.as_os_str().as_bytes()))
            )
        } else {
            header.fingerprint.clone()
        };
        keys.push(Key {
            id,
            path: path.clone(),
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            fingerprint: header.fingerprint,
            algorithm: header.algorithm,
            encrypted: header.encrypted,
            public_blob: header.public_blob,
            unavailable,
            unencrypted_copies: Vec::new(),
        });
    }
    let mut copies: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for k in &keys {
        if !k.encrypted && !k.fingerprint.is_empty() {
            copies.entry(k.id.clone()).or_default().push(k.path.clone());
        }
    }
    for k in &mut keys {
        k.unencrypted_copies = copies.get(&k.id).cloned().unwrap_or_default();
    }
    Ok(keys)
}
pub fn resolve<'a>(keys: &'a [Key], name: &str) -> Result<&'a Key> {
    let ids: BTreeSet<_> = keys
        .iter()
        .filter(|k| k.id == name || k.name == name || k.path.to_string_lossy() == name)
        .map(|k| &k.id)
        .collect();
    if ids.len() > 1 {
        return Err(Error("ambiguous_key"));
    }
    let id = ids.first().ok_or(Error("key_not_found"))?;
    keys.iter()
        .filter(|k| &k.id == *id)
        .min_by_key(|k| (!k.encrypted, k.unavailable.is_some()))
        .ok_or(Error("key_not_found"))
}
