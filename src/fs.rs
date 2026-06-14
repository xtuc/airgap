//! A directory-level passthrough FUSE overlay.
//!
//! The whole working directory is mounted through this filesystem, so every file
//! access — including files created *after* launch — is observed dynamically.
//! Ordinary files are proxied to the real filesystem; files that match a handler
//! (`.env` by name, private keys by content) are redacted on read and, for
//! `.env`, merged back on write.
//!
//! The backend reaches the real files through a captured dir fd to the working
//! directory (`root`, opened `O_PATH` before the mount shadowed the path) using
//! `*at` syscalls, so reads/writes of the real bytes never recurse back through
//! FUSE. Everything fails closed: a handler that can't redact/merge serves `EIO`
//! and never the raw bytes, and never corrupts the original.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    BsdFileFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, InitFlags, KernelConfig, LockOwner, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
    WriteFlags,
};
use nix::dir::{Dir, Type};
use nix::fcntl::{AtFlags, OFlag, openat, readlinkat, renameat};
use nix::libc;
use nix::sys::stat::{FileStat, Mode, SFlag, fstatat, mkdirat};
use nix::sys::uio::{pread, pwrite};
use nix::unistd::{UnlinkatFlags, ftruncate, symlinkat, unlinkat};

use crate::handlers::{self, HandlerKind};

/// How long the kernel may cache attributes/entries before asking again.
const TTL: Duration = Duration::from_secs(1);

/// The mount root inode.
const ROOT_INO: u64 = 1;

/// Map a `nix` errno to the `fuser` errno type used in replies.
fn errno(e: nix::errno::Errno) -> Errno {
    Errno::from_i32(e as i32)
}

/// The path to hand an `*at` call: the relative path, or `.` for the root itself
/// (an empty path would be `ENOENT`).
fn at(rel: &Path) -> &Path {
    if rel.as_os_str().is_empty() {
        Path::new(".")
    } else {
        rel
    }
}

/// What `read` should serve for a file, decided from its real contents.
enum View {
    /// Proxy the real file unchanged.
    Passthrough,
    /// `.env`: serve these redacted bytes; writes are merged back.
    Env(Vec<u8>),
    /// Private key: serve these redacted bytes; read-only.
    Key(Vec<u8>),
    /// A handler matched but failed to redact; fail closed (serve `EIO`).
    Failed,
}

/// State for one open file handle.
enum Handle {
    /// Passthrough: I/O goes straight to the real fd.
    File { fd: OwnedFd },
    /// `.env`: serve `served`; child writes accumulate in `pending`, merged on
    /// flush/release back through `fd` onto the original.
    Env {
        fd: OwnedFd,
        served: Vec<u8>,
        pending: Option<Vec<u8>>,
    },
    /// Private key: serve `served`; read-only.
    Key { served: Vec<u8> },
    /// Handler failed: every read fails closed with `EIO`.
    Failed,
}

/// Maps FUSE inodes to real paths (relative to `root`), assigned lazily.
struct InodeTable {
    by_ino: HashMap<u64, PathBuf>,
    by_path: HashMap<PathBuf, u64>,
    next: u64,
}

impl InodeTable {
    fn new() -> Self {
        let mut by_ino = HashMap::new();
        let mut by_path = HashMap::new();
        by_ino.insert(ROOT_INO, PathBuf::new());
        by_path.insert(PathBuf::new(), ROOT_INO);
        Self {
            by_ino,
            by_path,
            next: ROOT_INO + 1,
        }
    }

    fn intern(&mut self, path: PathBuf) -> u64 {
        if let Some(&ino) = self.by_path.get(&path) {
            return ino;
        }
        let ino = self.next;
        self.next += 1;
        self.by_ino.insert(ino, path.clone());
        self.by_path.insert(path, ino);
        ino
    }

    fn forget_path(&mut self, path: &Path) {
        if let Some(ino) = self.by_path.remove(path) {
            self.by_ino.remove(&ino);
        }
    }

    fn rename(&mut self, from: &Path, to: &Path) {
        if let Some(ino) = self.by_path.remove(from) {
            self.by_path.remove(to);
            self.by_ino.insert(ino, to.to_path_buf());
            self.by_path.insert(to.to_path_buf(), ino);
        }
    }
}

/// Allocates and stores open file handles.
struct Handles {
    next: u64,
    map: HashMap<u64, Handle>,
}

impl Handles {
    fn new() -> Self {
        Self {
            next: 1,
            map: HashMap::new(),
        }
    }

    fn insert(&mut self, handle: Handle) -> u64 {
        let id = self.next;
        self.next += 1;
        self.map.insert(id, handle);
        id
    }
}

/// The overlay filesystem.
pub struct OverlayFs {
    /// `O_PATH` dir fd to the real working directory, captured before the mount.
    root: OwnedFd,
    inodes: Mutex<InodeTable>,
    handles: Mutex<Handles>,
}

impl OverlayFs {
    pub fn new(root: OwnedFd) -> Self {
        Self {
            root,
            inodes: Mutex::new(InodeTable::new()),
            handles: Mutex::new(Handles::new()),
        }
    }

    fn root_fd(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }

    fn path_of(&self, ino: INodeNo) -> Option<PathBuf> {
        self.inodes.lock().unwrap().by_ino.get(&ino.0).cloned()
    }

    fn intern(&self, path: PathBuf) -> u64 {
        self.inodes.lock().unwrap().intern(path)
    }

    fn open_real(&self, rel: &Path, oflag: OFlag, mode: Mode) -> nix::Result<OwnedFd> {
        openat(self.root_fd(), at(rel), oflag, mode)
    }

    fn stat(&self, rel: &Path) -> nix::Result<FileStat> {
        fstatat(self.root_fd(), at(rel), AtFlags::AT_SYMLINK_NOFOLLOW)
    }

    /// Decide the read view for a regular file from its real contents.
    fn view_for(&self, rel: &Path, file_name: &OsStr) -> nix::Result<View> {
        let fd = self.open_real(rel, OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty())?;
        let mut prefix = [0u8; 64];
        let n = pread(fd.as_fd(), &mut prefix, 0).unwrap_or(0);
        match handlers::detect(file_name, &prefix[..n]) {
            None => Ok(View::Passthrough),
            Some(HandlerKind::Env) => {
                let original = read_all(fd.as_fd())?;
                Ok(match handlers::redact_env(&original) {
                    Ok(bytes) => View::Env(bytes),
                    Err(_) => View::Failed,
                })
            }
            Some(HandlerKind::PrivateKey) => {
                let original = read_all(fd.as_fd())?;
                Ok(match handlers::redact_private_key(&original) {
                    Some(bytes) => View::Key(bytes),
                    None => View::Passthrough,
                })
            }
        }
    }

    /// Live attributes: real metadata, but with the size of regular files that
    /// have a handler overridden to the redacted (served) length.
    fn attr(&self, ino: u64, rel: &Path) -> nix::Result<FileAttr> {
        let st = self.stat(rel)?;
        let mut attr = attr_from_stat(INodeNo(ino), &st);
        let is_regular =
            SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG;
        if is_regular {
            let name = rel.file_name().unwrap_or_default();
            match self.view_for(rel, name)? {
                View::Passthrough => {}
                View::Env(bytes) | View::Key(bytes) => {
                    attr.size = bytes.len() as u64;
                    attr.blocks = attr.size.div_ceil(512);
                }
                View::Failed => {
                    attr.size = 0;
                    attr.blocks = 0;
                }
            }
        }
        Ok(attr)
    }

    /// Merge an `.env` handle's pending writes back onto the original. Fails
    /// closed: a bad parse leaves the original untouched and drops the buffer.
    fn persist(&self, fh: u64) -> Result<(), Errno> {
        let mut handles = self.handles.lock().unwrap();
        let Some(Handle::Env { fd, served, pending }) = handles.map.get_mut(&fh) else {
            return Ok(());
        };
        let Some(written) = pending.take() else {
            return Ok(());
        };
        let original = read_all(fd.as_fd()).map_err(errno)?;
        // Parse/merge BEFORE touching the original — never corrupt on error.
        let merged = handlers::merge_env(&original, &written).map_err(|_| Errno::EIO)?;
        let view = handlers::redact_env(&merged).map_err(|_| Errno::EIO)?;
        ftruncate(fd.as_fd(), 0).map_err(errno)?;
        write_all_at(fd.as_fd(), &merged).map_err(errno)?;
        *served = view;
        Ok(())
    }
}

/// Read an entire fd from offset 0 via `pread`, without disturbing its offset.
pub fn read_all(fd: BorrowedFd) -> nix::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut offset = 0i64;
    loop {
        let n = pread(fd, &mut buf, offset)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        offset += n as i64;
    }
    Ok(out)
}

/// Write `data` to `fd` starting at offset 0 via `pwrite`.
fn write_all_at(fd: BorrowedFd, data: &[u8]) -> nix::Result<()> {
    let mut written = 0;
    while written < data.len() {
        let n = pwrite(fd, &data[written..], written as i64)?;
        if n == 0 {
            break;
        }
        written += n;
    }
    Ok(())
}

/// Build a `SystemTime` from a (seconds, nanoseconds) pair, as found in `stat`.
fn system_time(secs: i64, nsecs: i64) -> SystemTime {
    let nsecs = nsecs.clamp(0, 999_999_999) as u32;
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nsecs)
    } else {
        UNIX_EPOCH - Duration::new((-secs) as u64, 0) + Duration::new(0, nsecs)
    }
}

/// Translate a `stat` result into FUSE attributes, faithful to the real file
/// except for the inode number, which is the one we expose.
fn attr_from_stat(ino: INodeNo, st: &FileStat) -> FileAttr {
    let kind = match SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT {
        SFlag::S_IFDIR => FileType::Directory,
        SFlag::S_IFLNK => FileType::Symlink,
        SFlag::S_IFIFO => FileType::NamedPipe,
        SFlag::S_IFCHR => FileType::CharDevice,
        SFlag::S_IFBLK => FileType::BlockDevice,
        SFlag::S_IFSOCK => FileType::Socket,
        _ => FileType::RegularFile,
    };
    FileAttr {
        ino,
        size: st.st_size as u64,
        blocks: st.st_blocks as u64,
        atime: system_time(st.st_atime, st.st_atime_nsec),
        mtime: system_time(st.st_mtime, st.st_mtime_nsec),
        ctime: system_time(st.st_ctime, st.st_ctime_nsec),
        crtime: UNIX_EPOCH,
        kind,
        perm: (st.st_mode & 0o7777) as u16,
        nlink: st.st_nlink as u32,
        uid: st.st_uid,
        gid: st.st_gid,
        rdev: st.st_rdev as u32,
        blksize: st.st_blksize as u32,
        flags: 0,
    }
}

/// Map a `nix` directory entry type to a FUSE file type.
fn dir_type(t: Option<Type>) -> FileType {
    match t {
        Some(Type::Directory) => FileType::Directory,
        Some(Type::Symlink) => FileType::Symlink,
        Some(Type::Fifo) => FileType::NamedPipe,
        Some(Type::CharacterDevice) => FileType::CharDevice,
        Some(Type::BlockDevice) => FileType::BlockDevice,
        Some(Type::Socket) => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

/// Open flags for proxying a passthrough open: same access mode, plus append /
/// truncate if requested. Never `O_CREAT` (that path is `create`).
fn passthrough_oflag(flags: OpenFlags) -> OFlag {
    let mut oflag = OFlag::O_CLOEXEC;
    match flags.0 & libc::O_ACCMODE {
        libc::O_WRONLY => oflag |= OFlag::O_WRONLY,
        libc::O_RDWR => oflag |= OFlag::O_RDWR,
        _ => oflag |= OFlag::O_RDONLY,
    }
    if flags.0 & libc::O_APPEND != 0 {
        oflag |= OFlag::O_APPEND;
    }
    if flags.0 & libc::O_TRUNC != 0 {
        oflag |= OFlag::O_TRUNC;
    }
    oflag
}

impl Filesystem for OverlayFs {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        // Ask the kernel to deliver `O_TRUNC` in `open` (so we reset the pending
        // redacted buffer there) rather than as a separate fh-less `setattr`.
        let _ = config.add_capabilities(InitFlags::FUSE_ATOMIC_O_TRUNC);
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let rel = parent_path.join(name);
        match self.stat(&rel) {
            Ok(_) => {
                let ino = self.intern(rel.clone());
                match self.attr(ino, &rel) {
                    Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
                    Err(e) => reply.error(errno(e)),
                }
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let Some(rel) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.attr(ino.0, &rel) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let Some(rel) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        // A truncate on an open `.env` handle (e.g. `open(..., "w")`, delivered as
        // setattr(size) when atomic_o_trunc is off) resizes its pending redacted
        // view; the merge on flush reconciles it back to the original.
        if let (Some(sz), Some(fh)) = (size, fh) {
            let mut handles = self.handles.lock().unwrap();
            if let Some(Handle::Env { served, pending, .. }) = handles.map.get_mut(&fh.0) {
                pending.get_or_insert_with(|| served.clone()).resize(sz as usize, 0);
                drop(handles);
                match self.stat(&rel) {
                    Ok(st) => {
                        let mut attr = attr_from_stat(ino, &st);
                        attr.size = sz;
                        attr.blocks = sz.div_ceil(512);
                        reply.attr(&TTL, &attr);
                    }
                    Err(e) => reply.error(errno(e)),
                }
                return;
            }
        }
        // Truncation of a handler file is otherwise driven by open/write/flush; we
        // only act on the real file for passthrough, and refuse to truncate a
        // redacted key (which would mutate the original).
        if let Some(sz) = size {
            let name = rel.file_name().unwrap_or_default();
            match self.view_for(&rel, name) {
                Ok(View::Passthrough) => {
                    match self.open_real(&rel, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty()) {
                        Ok(fd) => {
                            if let Err(e) = ftruncate(fd.as_fd(), sz as i64) {
                                reply.error(errno(e));
                                return;
                            }
                        }
                        Err(e) => {
                            reply.error(errno(e));
                            return;
                        }
                    }
                }
                Ok(View::Env(_)) => {} // handled via the open handle's pending buffer
                Ok(View::Key(_)) => {
                    reply.error(Errno::EROFS);
                    return;
                }
                Ok(View::Failed) => {
                    reply.error(Errno::EIO);
                    return;
                }
                Err(e) => {
                    reply.error(errno(e));
                    return;
                }
            }
        }
        match self.attr(ino.0, &rel) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let Some(rel) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match readlinkat(self.root_fd(), at(&rel)) {
            Ok(target) => reply.data(target.as_bytes()),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let Some(rel) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let name = rel.file_name().unwrap_or_default().to_owned();
        let view = match self.view_for(&rel, &name) {
            Ok(v) => v,
            Err(e) => {
                reply.error(errno(e));
                return;
            }
        };
        let truncate = flags.0 & libc::O_TRUNC != 0;
        let handle = match view {
            View::Passthrough => {
                match self.open_real(&rel, passthrough_oflag(flags), Mode::empty()) {
                    Ok(fd) => Handle::File { fd },
                    Err(e) => {
                        reply.error(errno(e));
                        return;
                    }
                }
            }
            View::Env(served) => {
                // Need read+write to merge the edited view back on flush.
                match self.open_real(&rel, OFlag::O_RDWR | OFlag::O_CLOEXEC, Mode::empty()) {
                    Ok(fd) => {
                        Handle::Env {
                            fd,
                            // O_TRUNC means the child replaces the whole file:
                            // start its pending buffer empty.
                            pending: truncate.then(Vec::new),
                            served,
                        }
                    }
                    Err(e) => {
                        reply.error(errno(e));
                        return;
                    }
                }
            }
            View::Key(served) => Handle::Key { served },
            View::Failed => Handle::Failed,
        };
        let fh = self.handles.lock().unwrap().insert(handle);
        reply.opened(FileHandle(fh), FopenFlags::empty());
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let rel = parent_path.join(name);
        let mut oflag = OFlag::O_CREAT | OFlag::O_RDWR | OFlag::O_CLOEXEC;
        if flags & libc::O_TRUNC != 0 {
            oflag |= OFlag::O_TRUNC;
        }
        let perm = Mode::from_bits_truncate((mode & !umask) & 0o7777);
        let fd = match self.open_real(&rel, oflag, perm) {
            Ok(fd) => fd,
            Err(e) => {
                reply.error(errno(e));
                return;
            }
        };
        let ino = self.intern(rel.clone());
        // A freshly created file is empty; only `.env` files get a handler (a new
        // key file has no header yet). Its redacted view starts empty too.
        let handle = if handlers::is_env_file(name) {
            Handle::Env {
                fd,
                served: Vec::new(),
                pending: Some(Vec::new()),
            }
        } else {
            Handle::File { fd }
        };
        let fh = self.handles.lock().unwrap().insert(handle);
        match self.attr(ino, &rel) {
            Ok(attr) => reply.created(&TTL, &attr, Generation(0), FileHandle(fh), FopenFlags::empty()),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let handles = self.handles.lock().unwrap();
        match handles.map.get(&fh.0) {
            Some(Handle::File { fd }) => {
                let mut buf = vec![0u8; size as usize];
                match pread(fd.as_fd(), &mut buf, offset as i64) {
                    Ok(n) => reply.data(&buf[..n]),
                    Err(e) => reply.error(errno(e)),
                }
            }
            Some(Handle::Env { served, pending, .. }) => {
                let bytes = pending.as_ref().unwrap_or(served);
                let start = (offset as usize).min(bytes.len());
                let end = start.saturating_add(size as usize).min(bytes.len());
                reply.data(&bytes[start..end]);
            }
            Some(Handle::Key { served }) => {
                let start = (offset as usize).min(served.len());
                let end = start.saturating_add(size as usize).min(served.len());
                reply.data(&served[start..end]);
            }
            Some(Handle::Failed) => reply.error(Errno::EIO),
            None => reply.error(Errno::EBADF),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let mut handles = self.handles.lock().unwrap();
        match handles.map.get_mut(&fh.0) {
            Some(Handle::File { fd }) => match pwrite(fd.as_fd(), data, offset as i64) {
                Ok(n) => reply.written(n as u32),
                Err(e) => reply.error(errno(e)),
            },
            // Accumulate into the pending (redacted) buffer; merged on flush.
            Some(Handle::Env { served, pending, .. }) => {
                let buf = pending.get_or_insert_with(|| served.clone());
                let end = offset as usize + data.len();
                if buf.len() < end {
                    buf.resize(end, 0);
                }
                buf[offset as usize..end].copy_from_slice(data);
                reply.written(data.len() as u32);
            }
            Some(Handle::Key { .. }) => reply.error(Errno::EROFS),
            Some(Handle::Failed) => reply.error(Errno::EIO),
            None => reply.error(Errno::EBADF),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        // Merge here so a parse failure surfaces as a failed close().
        match self.persist(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        match self.persist(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        // Safety net for writers that skip flush; if flush already merged, the
        // pending buffer is empty and this is a no-op.
        let result = self.persist(fh.0);
        self.handles.lock().unwrap().map.remove(&fh.0);
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(dir_rel) = self.path_of(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let mut dir = match Dir::openat(
            self.root_fd(),
            at(&dir_rel),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(dir) => dir,
            Err(e) => {
                reply.error(errno(e));
                return;
            }
        };

        let mut entries: Vec<(u64, FileType, OsString)> = vec![
            (ino.0, FileType::Directory, OsString::from(".")),
            (ino.0, FileType::Directory, OsString::from("..")),
        ];
        for entry in dir.iter() {
            let Ok(entry) = entry else { continue };
            let raw = entry.file_name().to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            let name = OsStr::from_bytes(raw).to_owned();
            let child_ino = self.intern(dir_rel.join(&name));
            entries.push((child_ino, dir_type(entry.file_type()), name));
        }

        for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(*entry_ino), (i + 1) as u64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let rel = parent_path.join(name);
        let perm = Mode::from_bits_truncate((mode & !umask) & 0o7777);
        match mkdirat(self.root_fd(), at(&rel), perm) {
            Ok(()) => {
                let ino = self.intern(rel.clone());
                match self.attr(ino, &rel) {
                    Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
                    Err(e) => reply.error(errno(e)),
                }
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let rel = parent_path.join(name);
        match unlinkat(self.root_fd(), at(&rel), UnlinkatFlags::NoRemoveDir) {
            Ok(()) => {
                self.inodes.lock().unwrap().forget_path(&rel);
                reply.ok();
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let rel = parent_path.join(name);
        match unlinkat(self.root_fd(), at(&rel), UnlinkatFlags::RemoveDir) {
            Ok(()) => {
                self.inodes.lock().unwrap().forget_path(&rel);
                reply.ok();
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let (Some(parent_path), Some(newparent_path)) =
            (self.path_of(parent), self.path_of(newparent))
        else {
            reply.error(Errno::ENOENT);
            return;
        };
        let from = parent_path.join(name);
        let to = newparent_path.join(newname);
        match renameat(self.root_fd(), at(&from), self.root_fd(), at(&to)) {
            Ok(()) => {
                self.inodes.lock().unwrap().rename(&from, &to);
                reply.ok();
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let rel = parent_path.join(link_name);
        match symlinkat(target, self.root_fd(), at(&rel)) {
            Ok(()) => {
                let ino = self.intern(rel.clone());
                match self.attr(ino, &rel) {
                    Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
                    Err(e) => reply.error(errno(e)),
                }
            }
            Err(e) => reply.error(errno(e)),
        }
    }
}
