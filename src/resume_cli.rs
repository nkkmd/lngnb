//! R24/R26/R27/R30: 最新の実確認履歴に基づくローカル保存の明示再開と正常停止。
use super::AppError;
use lngnb::storage::{EvidenceRecoveryReview, StorageError, management::LocalResumeRequest};
use std::{ffi::OsString, fmt, io::Write, path::PathBuf};
#[derive(Debug, PartialEq, Eq)]
pub struct Command { path: PathBuf, request: LocalResumeRequest }
pub fn parse(args: &[OsString]) -> Result<Command,AppError> {
    let usage=||AppError::Usage("data resume-local に領域・確認受領値3項目・制限確認/再適用の明示・未解決障害がないと判断した理由を指定してください");
    let (mut path,mut source,mut recorded,mut count,mut confirmation)=(None,None,None,None,None);
    let mut restrictions=false;
    let mut args=args.iter();
    while let Some(option)=args.next() {
        if option=="--confirm-restrictions-reapplied" {
            if restrictions {return Err(usage());}
            restrictions=true;continue;
        }
        let value=args.next().ok_or_else(usage)?;
        if value.is_empty() {return Err(usage());}
        let integer=|| {
            let text=value.to_str().ok_or_else(usage)?;
            if text.len()>19 {return Err(usage());}
            let n=text.parse::<i64>().map_err(|_|usage())?;
            if n<0 || n.to_string()!=text {return Err(usage());}
            Ok(n)
        };
        match option.to_str() {
            Some("--data-dir") if path.is_none()=>path=Some(PathBuf::from(value)),
            Some("--source-generation") if source.is_none()=>source=Some(integer()?),
            Some("--review-generation") if recorded.is_none()=>recorded=Some(integer()?),
            Some("--checked-evidence") if count.is_none()=>count=Some(integer()? as u64),
            Some("--confirmation") if confirmation.is_none()=>confirmation=Some(value.to_str().ok_or_else(usage)?),
            _=>return Err(usage()),
        }
    }
    if !restrictions {return Err(usage());}
    Ok(Command {path:path.ok_or_else(usage)?,request:LocalResumeRequest::check(
        EvidenceRecoveryReview {source_generation:source.ok_or_else(usage)?,recorded_generation:recorded.ok_or_else(usage)?,checked_evidence:count.ok_or_else(usage)?},
        confirmation.ok_or_else(usage)?,
    ).map_err(|_|usage())?})
}
#[derive(Debug)]
pub enum Error { Resume(StorageError), Output }
impl Error {pub fn exit_code(&self)->u8 {if matches!(self,Self::Resume(_)) {3}else{1}}}
impl fmt::Display for Error {
    fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {
        match self {
            Self::Resume(error)=>write!(f,"{error}。ローカル保存の明示再開/正常停止を確認できません。再開履歴・評価・正常停止が保存済みまたは未確定の可能性があります。領域と履歴を保全し、手動待ち解除や正常停止を推測せず、自動再試行しないでください。現在状態と確認履歴を再確認してください。"),
            Self::Output=>f.write_str("この操作のローカル保存の明示再開と正常停止は確認しましたが、結果出力に失敗しました。記録を取り消したとは扱わず、再実行前に現在状態を確認してください。公開・IPCは再開していません。"),
        }
    }
}
impl std::error::Error for Error {}
pub fn run(command:Command,output:&mut impl Write)->Result<(),Error> {
    let receipt=command.request.resume_stopped(&command.path).map_err(Error::Resume)?;
    let text=format!("ローカル保存の明示再開と、この操作の正常停止を確認しました。\nreview_generation: {}\nresumed_generation: {}\nnormal_stop_confirmed: true\n世代は対象確認と再開履歴の受領値で、出力時の現在世代ではありません。一般配信・公開・IPCは再開していません。validや本文保持・pin・公開資格、恒久的な健全性、製品全体の復旧完了を保証しません。\n",receipt.review_generation,receipt.resumed_generation);
    report(&text,output)
}
fn report(text:&str,output:&mut impl Write)->Result<(),Error> {output.write_all(text.as_bytes()).and_then(|()|output.flush()).map_err(|_|Error::Output)}
#[cfg(test)]
mod tests {
    use super::*;
    fn args()->Vec<OsString> {["--data-dir","data","--source-generation","0","--review-generation","2","--checked-evidence","0","--confirmation","制限を確認/再適用済み、未解決障害なし","--confirm-restrictions-reapplied"].into_iter().map(Into::into).collect()}
    #[test]
    fn explicit_receipt_restrictions_and_reason_are_all_required_without_echo() {
        let a=args();assert!(parse(&a).is_ok());
        for i in (0..10).step_by(2) {
            let mut missing=a.clone();drop(missing.drain(i..i+2));assert!(parse(&missing).is_err());
            let mut duplicate=a.clone();duplicate.extend_from_slice(&a[i..i+2]);assert!(parse(&duplicate).is_err());
        }
        let mut no_flag=a.clone();no_flag.pop();assert!(parse(&no_flag).is_err());
        let mut duplicate=a.clone();duplicate.push(a[10].clone());assert!(parse(&duplicate).is_err());
        for i in [3,5,7] {for value in ["-1","+1","01","9223372036854775808","PRIVATE INPUT"] {let mut bad=a.clone();bad[i]=value.into();let e=parse(&bad).unwrap_err();assert!(!e.to_string().contains("PRIVATE INPUT"));}}
        for note in ["".to_owned()," \n".into(),"x".repeat(4097),"bad\0note".into()] {let mut bad=a.clone();bad[9]=note.into();assert!(parse(&bad).is_err());}
        let mut bad=a;bad.extend(["--restored".into(),"PRIVATE INPUT".into()]);assert!(parse(&bad).is_err());
    }
    #[test]
    fn resume_uncertainty_and_completed_output_failures_are_distinct() {
        let e=Error::Resume(StorageError::Io(std::io::Error::other("PRIVATE INPUT")));
        assert_eq!(e.exit_code(),3);assert!(!e.to_string().contains("PRIVATE INPUT"));assert!(std::error::Error::source(&e).is_none());
        assert_eq!(Error::Output.exit_code(),1);assert!(Error::Output.to_string().contains("正常停止は確認"));
        struct Sink(bool);impl Write for Sink {fn write(&mut self,b:&[u8])->std::io::Result<usize>{if self.0 {Ok(b.len())}else{Err(std::io::Error::other("test"))}}fn flush(&mut self)->std::io::Result<()>{Err(std::io::Error::other("test"))}}
        for flush in [false,true] {assert!(matches!(report("ok",&mut Sink(flush)),Err(Error::Output)));}
    }
}
