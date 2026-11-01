//! 固定管理socket名の非破壊観測。利用中/残存元/削除資格は判定しない。
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketPathKind { Socket, RegularFile, Directory, Symlink, Other }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketPathMetadata {
    pub kind: SocketPathKind,
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
    pub owner_gid: u32,
    /// 型bitを除くpermission/special bits。その値だけで安全性を認定しない。
    pub mode: u32,
    pub links: u64,
    pub byte_length: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}
impl SocketPathMetadata {
    fn from_metadata(m: &std::fs::Metadata)->Self {
        let kind=if m.file_type().is_socket(){SocketPathKind::Socket}
            else if m.file_type().is_symlink(){SocketPathKind::Symlink}
            else if m.is_file(){SocketPathKind::RegularFile}
            else if m.is_dir(){SocketPathKind::Directory}else{SocketPathKind::Other};
        Self {kind,device:m.dev(),inode:m.ino(),owner_uid:m.uid(),owner_gid:m.gid(),mode:m.mode() & 0o7777,links:m.nlink(),byte_length:m.len(),modified_seconds:m.mtime(),modified_nanoseconds:m.mtime_nsec(),changed_seconds:m.ctime(),changed_nanoseconds:m.ctime_nsec()}
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSocketPathEntry {
    /// 既存受理側と同じ固定名。任意pathや別endpointへ代替しない。
    pub name: &'static str,
    /// Noneはこの観測での不在。過去/今後の不在や削除済みの証明ではない。
    pub observed: Option<SocketPathMetadata>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSocketPathInventory {
    pub directory_device: u64,
    pub directory_inode: u64,
    pub owner_uid: u32,
    /// Record/RuntimeStatus/EvaluationStatus/Configurationの固定順。
    pub entries: [AdminSocketPathEntry;4],
}
impl RecordStore {
    /// 同じ排他とdirectory fdに束縛して、固定4名をNOFOLLOWで2回観測する。
    /// 一致した観測だけを返す。OS namespaceの原子的snapshotや不使用の証明ではない。
    /// payload/SQL/接続/要求送信/作成/削除/採用・writer/finish/手動待ち解除なし。
    /// elapsedは処理境界の予算で、lstat等のOS I/Oを強制中断しない。
    pub fn admin_socket_inventory(&self, elapsed: Duration)->std::result::Result<AdminSocketPathInventory,StorageError> {
        self.admin_socket_inventory_inner(elapsed,||Ok(()))
    }
    fn admin_socket_inventory_inner(&self,elapsed:Duration,after_first:impl FnOnce()->std::result::Result<(),StorageError>)->std::result::Result<AdminSocketPathInventory,StorageError> {
        let start=Instant::now();
        let check=||if start.elapsed()>=elapsed {Err(StorageError::BudgetExceeded)} else {Ok(())};
        let observe=|| -> std::result::Result<AdminSocketPathInventory,StorageError> {
            check()?;check_area(&self.dir)?;
            let directory=std::fs::metadata(anchored(&self.dir,"."))?;
            let mut entries=Vec::with_capacity(4);
            for name in [NAME,status::NAME,evaluation::NAME,configuration::NAME] {
                check()?;
                let observed=match std::fs::symlink_metadata(anchored(&self.dir,name)) {
                    Ok(m)=>Some(SocketPathMetadata::from_metadata(&m)),
                    Err(e) if e.kind()==std::io::ErrorKind::NotFound=>None,
                    Err(e)=>return Err(e.into()),
                };
                entries.push(AdminSocketPathEntry {name,observed});
            }
            check()?;
            Ok(AdminSocketPathInventory {directory_device:directory.dev(),directory_inode:directory.ino(),owner_uid:directory.uid(),entries:entries.try_into().map_err(|_|StorageError::UnsafePath)?})
        };
        let first=observe()?;
        after_first()?;
        let second=observe()?;
        check()?;
        if first!=second {return Err(StorageError::UnsafePath);}
        Ok(second)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Limits, StartupState, tests::{Temp,logical_snapshot}};
    use std::{fs,os::unix::fs::{PermissionsExt,symlink}};
    const ELAPSED:Duration=Duration::from_secs(60);
    #[test]
    fn fixed_paths_observe_live_and_dropped_sockets_without_contact_or_state_change() {
        let t=Temp::new();drop(t.store().begin().unwrap());
        let store=RecordStore::open(&t.data(),Limits::default()).unwrap();let before=logical_snapshot(&store.conn);
        let empty=store.admin_socket_inventory(ELAPSED).unwrap();
        assert_eq!(empty.entries.each_ref().map(|e|e.name),["admin.sock","admin-status.sock","admin-evaluate.sock","admin-config.sock"]);
        assert!(empty.entries.iter().all(|e|e.observed.is_none()));
        let mut listeners=Vec::new();
        for entry in &empty.entries {
            let path=anchored(&store.dir,entry.name);let listener=UnixListener::bind(&path).unwrap();
            fs::set_permissions(&path,fs::Permissions::from_mode(0o600)).unwrap();listener.set_nonblocking(true).unwrap();listeners.push(listener);
        }
        let live=store.admin_socket_inventory(ELAPSED).unwrap();
        for entry in &live.entries {
            let m=entry.observed.unwrap();assert_eq!(m.kind,SocketPathKind::Socket);assert_eq!(m.mode,0o600);assert_eq!(m.owner_uid,live.owner_uid);assert_eq!(m.links,1);
            let raw=fs::symlink_metadata(anchored(&store.dir,entry.name)).unwrap();assert_eq!((m.device,m.inode),(raw.dev(),raw.ino()));
        }
        for listener in &listeners {assert_eq!(listener.accept().unwrap_err().kind(),std::io::ErrorKind::WouldBlock);}
        drop(listeners);assert_eq!(store.admin_socket_inventory(ELAPSED).unwrap(),live);
        assert_eq!(logical_snapshot(&store.conn),before);assert_eq!(store.startup_state().unwrap(),StartupState::NeedsReview);
        assert!(RecordStore::open(&t.data(),Limits::default()).is_err());
    }
    #[test]
    fn unsafe_kinds_links_and_modes_remain_observations_without_following_or_repair() {
        let t=Temp::new();let store=t.store();let before=logical_snapshot(&store.conn);
        let original=t.root.join("public-original");fs::write(&original,b"PRIVATE CONTENT").unwrap();
        fs::hard_link(&original,anchored(&store.dir,NAME)).unwrap();
        symlink(&original,anchored(&store.dir,status::NAME)).unwrap();
        fs::create_dir(anchored(&store.dir,evaluation::NAME)).unwrap();
        let path=anchored(&store.dir,configuration::NAME);let socket=UnixListener::bind(&path).unwrap();fs::set_permissions(&path,fs::Permissions::from_mode(0o666)).unwrap();
        let result=store.admin_socket_inventory(ELAPSED).unwrap();
        assert_eq!(result.entries.each_ref().map(|e|e.observed.unwrap().kind),[SocketPathKind::RegularFile,SocketPathKind::Symlink,SocketPathKind::Directory,SocketPathKind::Socket]);
        assert_eq!(result.entries[0].observed.unwrap().links,2);assert_eq!(result.entries[3].observed.unwrap().mode,0o666);
        assert_eq!(fs::read(&original).unwrap(),b"PRIVATE CONTENT");assert!(fs::symlink_metadata(anchored(&store.dir,status::NAME)).unwrap().file_type().is_symlink());
        assert_eq!(logical_snapshot(&store.conn),before);assert_eq!(store.startup_state().unwrap(),StartupState::Clean);drop(socket);
    }
    #[test]
    fn budget_or_replaced_path_returns_no_partial_inventory_and_fd_remains_anchored() {
        let t=Temp::new();let store=t.store();let before=logical_snapshot(&store.conn);
        assert!(matches!(store.admin_socket_inventory(Duration::ZERO),Err(StorageError::BudgetExceeded)));
        let result=store.admin_socket_inventory_inner(ELAPSED,||{fs::write(anchored(&store.dir,NAME),b"created between observations")?;Ok(())});
        assert!(matches!(result,Err(StorageError::UnsafePath)));
        let replaced=store.admin_socket_inventory_inner(ELAPSED,||{
            let path=anchored(&store.dir,NAME);fs::rename(&path,t.root.join("previous-node"))?;
            fs::write(&path,b"created between observations")?;Ok(())
        });assert!(matches!(replaced,Err(StorageError::UnsafePath)));
        let changed=store.admin_socket_inventory_inner(ELAPSED,||{let path=anchored(&store.dir,NAME);let mode=if fs::symlink_metadata(&path)?.mode() & 0o7777==0o600 {0o400}else{0o600};fs::set_permissions(path,fs::Permissions::from_mode(mode))?;Ok(())});
        assert!(matches!(changed,Err(StorageError::UnsafePath)));
        let stable=store.admin_socket_inventory(ELAPSED).unwrap();
        let renamed=t.root.join("original-area");fs::rename(t.data(),&renamed).unwrap();fs::create_dir(t.data()).unwrap();
        fs::write(t.data().join(NAME),b"different area").unwrap();
        assert_eq!(store.admin_socket_inventory(ELAPSED).unwrap(),stable);
        assert_eq!(logical_snapshot(&store.conn),before);
        assert_eq!(fs::read(renamed.join(NAME)).unwrap(),b"created between observations");assert_eq!(fs::read(t.data().join(NAME)).unwrap(),b"different area");
    }
}
