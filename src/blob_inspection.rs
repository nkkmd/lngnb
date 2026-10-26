//! RecordInspectionのBlob段階。上限付き一覧を固定し、全体hashをファイル単位で再開。
use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone)]
struct Entry {
    area: String,
    name: String,
    expected: Option<i64>,
    size: Option<i64>,
    fingerprint: Option<String>,
    result: String,
    examined: i64,
}
struct Inventory {
    epoch: i64,
    blobs: String,
    staging: String,
    digest: [u8; 32],
}
pub(super) struct BlobPlan {
    inventory: Inventory,
    rows: Vec<Entry>,
    changed: Vec<usize>,
    fresh: bool,
    pub(super) done: bool,
    pub(super) files: i64,
    pub(super) bytes: i64,
}
fn directories(store: &RecordStore) -> Result<(OwnedFd, OwnedFd, String, String)> {
    let blobs = blobs::blob_directory(&store.dir, "blobs")?;
    let staging = blobs::blob_directory(&store.dir, "staging")?;
    let b = fingerprint(&std::fs::metadata(anchored(&blobs, "."))?);
    let s = fingerprint(&std::fs::metadata(anchored(&staging, "."))?);
    Ok((blobs, staging, b, s))
}
fn digest(rows: &[Entry]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"lngnb:blob-inspection-manifest:1\0");
    for row in rows {
        for s in [
            &row.area,
            &row.name,
            row.fingerprint.as_deref().unwrap_or(""),
            &row.result,
        ] {
            h.update((s.len() as u64).to_be_bytes());
            h.update(s.as_bytes());
        }
        h.update(row.expected.unwrap_or(-1).to_be_bytes());
        h.update(row.size.unwrap_or(-1).to_be_bytes());
        h.update(row.examined.to_be_bytes());
    }
    h.finalize().into()
}
fn id(row: &Entry) -> Result<Id> {
    let stem = if row.area == "staging" {
        row.name
            .strip_suffix(".part")
            .ok_or(StorageError::Corrupt)?
    } else {
        &row.name
    };
    blobs::parse_name(stem)
}
// 読取りだけを囲み、checkpoint保存・ファイルI/O・quick_checkとはscopeを分ける。
fn load(
    store: &RecordStore,
    epoch: i64,
    budget: SqlInspectionBudget,
) -> Result<Option<(Inventory, Vec<Entry>)>> {
    sql_inspection::run(&store.conn, budget, || load_inner(store, epoch))
}
fn load_inner(store: &RecordStore, epoch: i64) -> Result<Option<(Inventory, Vec<Entry>)>> {
    let header:Option<(i64,String,String,Vec<u8>)>=store.conn.query_row("SELECT epoch,blobs_fingerprint,staging_fingerprint,digest FROM blob_inspection_inventory WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let Some((saved, b, s, hash)) = header else {
        let n: i64 =
            store
                .conn
                .query_row("SELECT count(*) FROM blob_inspection_files", [], |r| {
                    r.get(0)
                })?;
        if n != 0 {
            return Err(StorageError::Corrupt);
        }
        return Ok(None);
    };
    if saved != epoch {
        return Err(StorageError::Corrupt);
    }
    let mut rows = Vec::new();
    let mut stmt=store.conn.prepare("SELECT area,name,expected_length,size,fingerprint,result,examined_bytes FROM blob_inspection_files ORDER BY area,name")?;
    let mut result = stmt.query([])?;
    while let Some(r) = result.next()? {
        if rows.len() as u64 >= store.limits.scan_blob_files.saturating_mul(2) {
            return Err(StorageError::BudgetExceeded);
        }
        let row = Entry {
            area: r.get(0)?,
            name: r.get(1)?,
            expected: r.get(2)?,
            size: r.get(3)?,
            fingerprint: r.get(4)?,
            result: r.get(5)?,
            examined: r.get(6)?,
        };
        id(&row)?;
        if !["blobs", "staging"].contains(&row.area.as_str())
            || row.expected.is_some_and(|n| n < 0)
            || row.size.is_some_and(|n| n < 0)
            || row.size.is_some() != row.fingerprint.is_some()
            || (row.area == "staging" && (row.expected.is_some() || row.size.is_none()))
            || (row.size.is_none() && row.expected.is_none())
            || row.examined < 0
            || row.examined > row.size.unwrap_or(0)
            || ![
                "pending",
                "verified",
                "orphaned",
                "missing",
                "corrupt",
                "incomplete",
            ]
            .contains(&row.result.as_str())
            || (row.result == "pending" && row.examined != 0)
        {
            return Err(StorageError::Corrupt);
        }
        rows.push(row);
    }
    let hash: [u8; 32] = hash.try_into().map_err(|_| StorageError::Corrupt)?;
    if digest(&rows) != hash {
        return Err(StorageError::Corrupt);
    }
    let (ledger, listed): (i64,i64) = store.conn.query_row(
        "SELECT (SELECT count(*) FROM blobs),(SELECT count(*) FROM blob_inspection_files WHERE expected_length IS NOT NULL)",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
    let mismatch:bool=store.conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM blobs b LEFT JOIN blob_inspection_files f ON f.area='blobs' AND f.name=lower(hex(b.id)) WHERE f.expected_length IS NULL OR f.expected_length!=b.byte_length)",[],|r|r.get(0))?;
    if ledger != listed || mismatch {
        return Err(StorageError::Corrupt);
    }
    Ok(Some((
        Inventory {
            epoch: saved,
            blobs: b,
            staging: s,
            digest: hash,
        },
        rows,
    )))
}
fn inventory(store: &RecordStore, epoch: i64) -> Result<(Inventory, Vec<Entry>)> {
    let (bdir, sdir, before_b, before_s) = directories(store)?;
    let mut entries = BTreeMap::new();
    let mut stmt = store
        .conn
        .prepare("SELECT id,byte_length FROM blobs ORDER BY id")?;
    let mut results = stmt.query([])?;
    let mut count = 0u64;
    while let Some(r) = results.next()? {
        if count >= store.limits.scan_blob_files {
            return Err(StorageError::BudgetExceeded);
        }
        count += 1;
        let raw: Vec<u8> = r.get(0)?;
        let raw: [u8; 32] = raw.try_into().map_err(|_| StorageError::Corrupt)?;
        let length: i64 = r.get(1)?;
        if length < 0 {
            return Err(StorageError::Corrupt);
        }
        let name = blobs::hex(&raw);
        entries.insert(
            ("blobs".to_owned(), name.clone()),
            Entry {
                area: "blobs".into(),
                name,
                expected: Some(length),
                size: None,
                fingerprint: None,
                result: "pending".into(),
                examined: 0,
            },
        );
    }
    let mut remaining = store.limits.scan_blob_files;
    for (area, dir) in [("blobs", &bdir), ("staging", &sdir)] {
        for name in blobs::entries(dir, &mut remaining)? {
            let mut row = entries
                .remove(&(area.to_owned(), name.clone()))
                .unwrap_or(Entry {
                    area: area.into(),
                    name,
                    expected: None,
                    size: None,
                    fingerprint: None,
                    result: "pending".into(),
                    examined: 0,
                });
            id(&row)?;
            let file = blobs::checked_file(dir, &row.name)?;
            let m = file.metadata()?;
            row.size = Some(i64::try_from(m.len()).map_err(|_| StorageError::BudgetExceeded)?);
            row.fingerprint = Some(fingerprint(&m));
            entries.insert((row.area.clone(), row.name.clone()), row);
        }
    }
    let (_, _, after_b, after_s) = directories(store)?;
    if before_b != after_b || before_s != after_s {
        return Err(StorageError::Corrupt);
    }
    let rows: Vec<_> = entries.into_values().collect();
    let hash = digest(&rows);
    Ok((
        Inventory {
            epoch,
            blobs: after_b,
            staging: after_s,
            digest: hash,
        },
        rows,
    ))
}
fn validate_files(store: &RecordStore, saved: &Inventory, rows: &[Entry]) -> Result<()> {
    let (bdir, sdir, b, s) = directories(store)?;
    if b != saved.blobs || s != saved.staging {
        return Err(StorageError::Corrupt);
    }
    // 再開時も過去の検査を無条件に使わず、一覧全体のstatを照合する。
    for row in rows {
        let dir = if row.area == "blobs" { &bdir } else { &sdir };
        match blobs::checked_file(dir, &row.name) {
            Ok(file) => {
                if row.fingerprint.as_deref() != Some(fingerprint(&file.metadata()?).as_str()) {
                    return Err(StorageError::Corrupt);
                }
            }
            Err(StorageError::Io(e))
                if e.kind() == std::io::ErrorKind::NotFound && row.fingerprint.is_none() => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn totals(rows: &[Entry]) -> Result<(i64, i64)> {
    rows.iter()
        .filter(|r| r.result != "pending")
        .try_fold((0i64, 0i64), |(n, b), r| {
            Ok((
                n.checked_add(1).ok_or(StorageError::Corrupt)?,
                b.checked_add(r.examined).ok_or(StorageError::Corrupt)?,
            ))
        })
}
pub(super) fn prepare(
    store: &RecordStore,
    epoch: i64,
    checked: (i64, i64),
    budget: InspectionBudget,
    start: Instant,
) -> Result<BlobPlan> {
    let (mut saved, mut rows, fresh) = match load(
        store,
        epoch,
        store.limits.sql_inspection.within(start, budget.elapsed),
    )? {
        Some((saved, rows)) => (saved, rows, false),
        None => {
            let (s, r) = inventory(store, epoch)?;
            (s, r, true)
        }
    };
    if totals(&rows)? != checked {
        return Err(StorageError::Corrupt);
    }
    validate_files(store, &saved, &rows)?;
    let cap = budget.blob_bytes.min(store.limits.scan_blob_bytes);
    if budget.blob_files == 0 || cap == 0 {
        return Err(StorageError::BudgetExceeded);
    }
    let mut work = 0u64;
    let mut bytes = 0u64;
    let mut changed = Vec::new();
    let bdir = blobs::blob_directory(&store.dir, "blobs")?;
    for (index, row) in rows.iter_mut().enumerate() {
        if row.result != "pending" {
            continue;
        }
        if work >= budget.blob_files || start.elapsed() >= budget.elapsed {
            break;
        }
        let expected_mismatch = matches!((row.expected,row.size),(Some(a),Some(b)) if a!=b);
        let cost = if row.area == "blobs" && !expected_mismatch {
            row.size.unwrap_or(0) as u64
        } else {
            0
        };
        if cost > cap - bytes {
            if work == 0 {
                return Err(StorageError::BudgetExceeded);
            }
            break;
        }
        row.result = if row.area == "staging" {
            "incomplete".into()
        } else if row.size.is_none() {
            "missing".into()
        } else if expected_mismatch {
            "corrupt".into()
        } else {
            match blobs::verify_file(&bdir, id(row)?, row.expected.map(|n| n as u64), cap - bytes) {
                Ok(_) => {
                    if row.expected.is_some() {
                        "verified".into()
                    } else {
                        "orphaned".into()
                    }
                }
                Err(StorageError::Corrupt) => "corrupt".into(),
                Err(e) => return Err(e),
            }
        };
        row.examined = cost as i64;
        bytes += cost;
        work += 1;
        changed.push(index);
    }
    validate_files(store, &saved, &rows)?;
    let pending = rows.iter().any(|r| r.result == "pending");
    if pending && work == 0 {
        return Err(StorageError::BudgetExceeded);
    }
    let mut done = !pending && start.elapsed() < budget.elapsed;
    if done {
        let check: String = sql_inspection::run(
            &store.conn,
            store.limits.sql_inspection.within(start, budget.elapsed),
            || {
                Ok(store
                    .conn
                    .query_row("PRAGMA quick_check", [], |r| r.get(0))?)
            },
        )?;
        if check != "ok" {
            return Err(StorageError::Corrupt);
        }
        done = start.elapsed() < budget.elapsed;
    }
    if !done && work == 0 {
        return Err(StorageError::BudgetExceeded);
    }
    saved.digest = digest(&rows);
    let (files, bytes) = totals(&rows)?;
    Ok(BlobPlan {
        inventory: saved,
        rows,
        changed,
        fresh,
        done,
        files,
        bytes,
    })
}
pub(super) fn reset(tx: &Transaction<'_>) -> Result<()> {
    tx.execute("DELETE FROM blob_inspection_files", [])?;
    tx.execute("DELETE FROM blob_inspection_inventory", [])?;
    Ok(())
}
impl BlobPlan {
    pub(super) fn apply(&self, tx: &Transaction<'_>) -> Result<()> {
        if self.fresh {
            reset(tx)?;
            tx.execute(
                "INSERT INTO blob_inspection_inventory VALUES(1,?1,?2,?3,?4)",
                params![
                    self.inventory.epoch,
                    &self.inventory.blobs,
                    &self.inventory.staging,
                    &self.inventory.digest
                ],
            )?;
            for row in &self.rows {
                tx.execute(
                    "INSERT INTO blob_inspection_files VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        &row.area,
                        &row.name,
                        row.expected,
                        row.size,
                        &row.fingerprint,
                        &row.result,
                        row.examined
                    ],
                )?;
            }
        } else {
            for index in &self.changed {
                let row = &self.rows[*index];
                if tx.execute("UPDATE blob_inspection_files SET result=?1,examined_bytes=?2 WHERE area=?3 AND name=?4 AND result='pending'",params![&row.result,row.examined,&row.area,&row.name])?!=1{return Err(StorageError::Corrupt);}
            }
        }
        if tx.execute(
            "UPDATE blob_inspection_inventory SET digest=?1 WHERE singleton=1 AND epoch=?2",
            params![&self.inventory.digest, self.inventory.epoch],
        )? != 1
        {
            return Err(StorageError::Corrupt);
        }
        Ok(())
    }
    pub(super) fn report(&self) -> Result<BlobRecovery> {
        report(&self.rows)
    }
}
fn report(rows: &[Entry]) -> Result<BlobRecovery> {
    let mut report = BlobRecovery::default();
    for row in rows {
        match row.result.as_str() {
            "pending" | "verified" => (),
            "incomplete" => report.incomplete_staging.push(row.name.clone()),
            "missing" => report.missing.push(id(row)?),
            "corrupt" => report.corrupt.push(id(row)?),
            "orphaned" => report.orphaned.push(id(row)?),
            _ => return Err(StorageError::Corrupt),
        }
    }
    Ok(report)
}
pub(super) fn restore(
    store: &RecordStore,
    epoch: i64,
    checked: (i64, i64),
) -> Result<BlobRecovery> {
    if let Some((_, rows)) = load(store, epoch, store.limits.sql_inspection)? {
        if totals(&rows)? != checked {
            return Err(StorageError::Corrupt);
        }
        report(&rows)
    } else {
        if checked != (0, 0) {
            return Err(StorageError::Corrupt);
        }
        Ok(BlobRecovery::default())
    }
}

pub(super) fn validate_complete(
    store: &RecordStore,
    epoch: i64,
    checked: (i64, i64),
) -> Result<()> {
    let (saved, rows) =
        load(store, epoch, store.limits.sql_inspection)?.ok_or(StorageError::Corrupt)?;
    if totals(&rows)? != checked || rows.iter().any(|r| r.result == "pending") {
        return Err(StorageError::Corrupt);
    }
    validate_files(store, &saved, &rows)
}
#[cfg(test)]
#[path = "blob_inspection_tests.rs"]
mod tests;
