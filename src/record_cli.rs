//! 完成署名Record一件を明示したローカル管理socketへ送る。署名/直接保存は行わない。
use super::AppError;
use lngnb::{
    authoring_input,
    id::{Id, Kind},
    record::LocalRecord,
    storage::{ManualPublicationChange, admin_transport::client, management::Receipt},
};
use std::{ffi::OsString, fmt, io::Write, path::PathBuf, time::Duration};

#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    data: PathBuf,
    operation: Operation,
}
#[derive(Debug, PartialEq, Eq)]
enum Operation {
    Submit(PathBuf),
    Pin {
        knowledge: Id,
        genesis: Option<Id>,
        reason: String,
    },
    Publication {
        id: Id,
        reason: String,
        change: ManualPublicationChange,
    },
}
pub fn parse(args: &[OsString]) -> Result<Command, AppError> {
    let usage =
        || AppError::Usage("record submit --data-dir PATH --record PATH を指定してください");
    let [action, rest @ ..] = args else {
        return Err(usage());
    };
    if action == "pin" || action == "unpin" {
        return parse_pin(rest, action == "pin");
    }
    if action == "revoke-publication" {
        return parse_publication(rest, false);
    }
    if action == "approve-publication" {
        return parse_publication(rest, true);
    }
    if action != "submit" || rest.len() != 4 {
        return Err(usage());
    }
    let mut data = None;
    let mut record = None;
    for pair in rest.chunks_exact(2) {
        if pair[1].is_empty() {
            return Err(usage());
        }
        match pair[0].to_str() {
            Some("--data-dir") if data.is_none() => data = Some(PathBuf::from(&pair[1])),
            Some("--record") if record.is_none() => record = Some(PathBuf::from(&pair[1])),
            _ => return Err(usage()),
        }
    }
    Ok(Command {
        data: data.ok_or_else(usage)?,
        operation: Operation::Submit(record.ok_or_else(usage)?),
    })
}
fn parse_pin(args: &[OsString], set: bool) -> Result<Command, AppError> {
    let usage = || {
        AppError::Usage(if set {
            "record pin --data-dir PATH --knowledge-id ID --genesis-id ID --reason TEXT を指定してください"
        } else {
            "record unpin --data-dir PATH --knowledge-id ID --reason TEXT を指定してください"
        })
    };
    if args.len() != if set { 8 } else { 6 } {
        return Err(usage());
    }
    let (mut data, mut knowledge, mut genesis, mut reason) = (None, None, None, None);
    for pair in args.chunks_exact(2) {
        let parse_id =
            |kind| Id::parse(kind, pair[1].to_str().ok_or_else(usage)?).map_err(|_| usage());
        match pair[0].to_str() {
            Some("--data-dir") if data.is_none() && !pair[1].is_empty() => {
                data = Some(PathBuf::from(&pair[1]))
            }
            Some("--knowledge-id") if knowledge.is_none() => {
                knowledge = Some(parse_id(Kind::Knowledge)?)
            }
            Some("--genesis-id") if set && genesis.is_none() => {
                genesis = Some(parse_id(Kind::Record)?)
            }
            Some("--reason") if reason.is_none() => {
                reason = Some(
                    pair[1]
                        .to_str()
                        .filter(|s| s.len() <= 1024 && !s.trim().is_empty())
                        .ok_or_else(usage)?
                        .to_owned(),
                )
            }
            _ => return Err(usage()),
        }
    }
    Ok(Command {
        data: data.ok_or_else(usage)?,
        operation: Operation::Pin {
            knowledge: knowledge.ok_or_else(usage)?,
            genesis: if set {
                Some(genesis.ok_or_else(usage)?)
            } else {
                None
            },
            reason: reason.ok_or_else(usage)?,
        },
    })
}
fn parse_publication(args: &[OsString], approve: bool) -> Result<Command, AppError> {
    let usage = || {
        AppError::Usage(if approve {
            "record approve-publication --data-dir PATH --record-id ID --mode public|untrusted --reason TEXT を指定してください"
        } else {
            "record revoke-publication --data-dir PATH --record-id ID --reason TEXT を指定してください"
        })
    };
    if args.len() != if approve { 8 } else { 6 } {
        return Err(usage());
    }
    let (mut data, mut id, mut reason) = (None, None, None);
    let mut change = (!approve).then_some(ManualPublicationChange::Revoke);
    for pair in args.chunks_exact(2) {
        match pair[0].to_str() {
            Some("--data-dir") if data.is_none() && !pair[1].is_empty() => {
                data = Some(PathBuf::from(&pair[1]))
            }
            Some("--record-id") if id.is_none() => {
                id = Some(
                    Id::parse(Kind::Record, pair[1].to_str().ok_or_else(usage)?)
                        .map_err(|_| usage())?,
                )
            }
            Some("--mode") if change.is_none() => {
                change = Some(match pair[1].to_str() {
                    Some("public") => ManualPublicationChange::ApprovePublic,
                    Some("untrusted") => ManualPublicationChange::ApproveUntrusted,
                    _ => return Err(usage()),
                });
            }
            Some("--reason") if reason.is_none() => {
                reason = Some(
                    pair[1]
                        .to_str()
                        .filter(|reason| reason.len() <= 1024 && !reason.trim().is_empty())
                        .ok_or_else(usage)?
                        .to_owned(),
                )
            }
            _ => return Err(usage()),
        }
    }
    Ok(Command {
        data: data.ok_or_else(usage)?,
        operation: Operation::Publication {
            id: id.ok_or_else(usage)?,
            reason: reason.ok_or_else(usage)?,
            change: change.ok_or_else(usage)?,
        },
    })
}
#[derive(Debug)]
pub enum Error {
    Input,
    InvalidRecord,
    Pin(client::Error),
    PinTarget,
    PinOutput,
    Revoke(client::Error),
    Approval(client::Error),
    ApprovalTargetMissing,
    ApprovalOutput,
    RevokeTargetMissing,
    RevokeOutput,
    Client(client::Error),
    Output,
}
impl Error {
    pub fn exit_code(&self) -> u8 {
        if matches!(
            self,
            Self::Client(client::Error::OutcomeUnknown)
                | Self::Revoke(client::Error::OutcomeUnknown)
                | Self::Approval(client::Error::OutcomeUnknown)
                | Self::Pin(client::Error::OutcomeUnknown)
        ) {
            3
        } else {
            1
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Input => "完成Record入力の読取りを完了できません。送信していません。",
            Self::InvalidRecord => "完成Recordの局所検査に失敗しました。送信していません。",
            Self::Client(client::Error::OutcomeUnknown) => "Recordの保存確定を確認できません。保存済みの可能性があります。入力と保存領域を保全して確認してください。自動再送・直接保存への切替は行っていません。",
            Self::Client(_) => "管理接続先を確認できず、Recordは送信していません。初期化・socket削除・直接保存への切替は行っていません。",
            Self::Revoke(client::Error::OutcomeUnknown) => "公開取消しの確定を確認できません。自動再送は行っていません。",
            Self::Approval(client::Error::OutcomeUnknown) => "公開承認の確定を確認できません。自動再送は行っていません。",
            Self::Pin(client::Error::OutcomeUnknown) => "pinの確定を確認できません。自動再送は行っていません。",
            Self::Pin(_) => "pinの管理要求を送信できませんでした。",
            Self::PinTarget => "対象Knowledgeの保存済みGenesisを確認できません。",
            Self::PinOutput => "pinの確定応答を照合しましたが、結果の出力に失敗しました。",
            Self::Approval(_) => "公開承認要求を送信できませんでした。",
            Self::ApprovalTargetMissing => "対象Recordが存在しないため公開承認を保存しませんでした。",
            Self::ApprovalOutput => "公開承認は確定しましたが、結果の出力に失敗しました。",
            Self::Revoke(_) => "公開取消し要求を送信できませんでした。",
            Self::RevokeTargetMissing => "対象Recordが存在しないため公開取消しを保存しませんでした。",
            Self::RevokeOutput => "公開取消しは確定しましたが、結果の出力に失敗しました。",
            Self::Output => "Record一件のローカル保存確定応答を照合しましたが、結果出力に失敗しました。再作成せず保存領域を確認してください。",
        })
    }
}
impl std::error::Error for Error {}
pub fn run(command: Command, output: &mut impl Write) -> Result<(), Error> {
    let path = match command.operation {
        Operation::Submit(path) => path,
        Operation::Pin {
            knowledge,
            genesis,
            reason,
        } => {
            let changed = client::change_pin(
                &command.data,
                knowledge,
                genesis,
                &reason,
                Duration::from_secs(30),
            )
            .map_err(Error::Pin)?
            .ok_or(Error::PinTarget)?;
            return writeln!(
                output,
                "pinの確定応答を照合しました。\nknowledge_id: {knowledge}\nchanged: {changed}"
            )
            .and_then(|()| output.flush())
            .map_err(|_| Error::PinOutput);
        }
        Operation::Publication { id, reason, change }
            if change != ManualPublicationChange::Revoke =>
        {
            let confirmed = client::change_publication(
                &command.data,
                id,
                &reason,
                change,
                Duration::from_secs(30),
            )
            .map_err(Error::Approval)?;
            if !confirmed {
                return Err(Error::ApprovalTargetMissing);
            }
            return writeln!(
                output,
                "公開承認の保存確定応答を照合しました。\nrecord_id: {id}"
            )
            .and_then(|()| output.flush())
            .map_err(|_| Error::ApprovalOutput);
        }
        Operation::Publication { id, reason, .. } => {
            if !client::revoke_publication(&command.data, id, &reason, Duration::from_secs(30))
                .map_err(Error::Revoke)?
            {
                return Err(Error::RevokeTargetMissing);
            }
            return writeln!(
                output,
                "公開取消しの保存確定応答を照合しました。\nrecord_id: {id}"
            )
            .and_then(|()| output.flush())
            .map_err(|_| Error::RevokeOutput);
        }
    };
    let bytes = authoring_input::read_record_file(&path).map_err(|_| Error::Input)?;
    let record = LocalRecord::check(&bytes, None).map_err(|_| Error::InvalidRecord)?;
    let receipt =
        client::submit(&command.data, &record, Duration::from_secs(30)).map_err(Error::Client)?;
    report(receipt, output)
}
fn report(receipt: Receipt, output: &mut impl Write) -> Result<(), Error> {
    let text = format!(
        "Record一件のローカル保存確定応答を照合しました。\nrecord_id: {}\ninserted: {}\n親評価完了・本文保持・pin・公開・正常停止・復旧完了の判定ではありません。\n",
        receipt.record_id, receipt.inserted
    );
    output
        .write_all(text.as_bytes())
        .and_then(|()| output.flush())
        .map_err(|_| Error::Output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_unique_paths_and_unknown_arguments_never_echo_inputs() {
        let good: Vec<OsString> = [
            "submit",
            "--record",
            "record 日本語",
            "--data-dir",
            "data space",
        ]
        .map(Into::into)
        .to_vec();
        assert_eq!(parse(&good).unwrap().data, PathBuf::from("data space"));
        for args in [
            vec![],
            vec!["submit"],
            vec!["submit", "--data-dir", "a", "--data-dir", "b"],
            vec!["submit", "--data-dir", "", "--record", "b"],
            vec!["private", "--data-dir", "a", "--record", "b"],
        ] {
            let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
            assert!(!parse(&args).unwrap_err().to_string().contains("private"));
        }
    }
    #[test]
    fn uncertainty_and_confirmed_output_failure_are_distinct() {
        for kind in [
            client::Error::Policy,
            client::Error::Endpoint,
            client::Error::Connect,
            client::Error::Unauthorized,
            client::Error::OutcomeUnknown,
        ] {
            let e = Error::Client(kind);
            assert_eq!(
                e.exit_code(),
                if kind == client::Error::OutcomeUnknown {
                    3
                } else {
                    1
                }
            );
            assert!(std::error::Error::source(&e).is_none());
        }
        struct Sink(bool);
        impl Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if self.0 {
                    Ok(b.len())
                } else {
                    Err(std::io::Error::other("private"))
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("private"))
            }
        }
        for flush in [false, true] {
            let receipt = Receipt {
                record_id: lngnb::id::record_id(b"test"),
                inserted: true,
            };
            assert!(matches!(
                report(receipt, &mut Sink(flush)),
                Err(Error::Output)
            ));
        }
    }
}
