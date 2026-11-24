//! 明示設定した公開基底URLと、照合済みの三つのIDから固定引用を組み立てる。

use crate::fixed_record_http::parse_host_authority;
use crate::id::{Id, Kind};
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Eq)]
pub struct PublicBaseUrl(String);

#[derive(Debug, PartialEq, Eq)]
pub struct Citation {
    pub reference: String,
    pub url: String,
}

impl PublicBaseUrl {
    /// HTTPSのauthorityと、空または正規の基底パスを受け入れる。
    pub fn parse(value: &str) -> Option<Self> {
        let rest = value.strip_prefix("https://")?;
        let (authority, path) = rest
            .split_once('/')
            .map_or((rest, None), |(host, path)| (host, Some(path)));
        let (host, port) = parse_host_authority(authority)?;
        let host_text = if authority.starts_with('[') {
            authority.split_once(']')?.0.strip_prefix('[')?
        } else {
            authority.split(':').next()?
        };
        if host_text != host || port == Some(0) {
            return None;
        }
        // 数値で終わる名前はブラウザーがIPv4として解釈し得る。
        if !host.contains(':') && host.parse::<Ipv4Addr>().is_err() {
            let last = host.rsplit('.').next()?;
            if last.bytes().all(|byte| byte.is_ascii_digit())
                || last
                    .to_ascii_lowercase()
                    .strip_prefix("0x")
                    .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                return None;
            }
        }
        if path.is_some_and(|path| {
            path.split('/').any(|segment| {
                segment.is_empty()
                    || matches!(segment, "." | "..")
                    || !segment
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
            })
        }) {
            return None;
        }
        Some(Self(value.to_owned()))
    }

    pub fn api_base_url(&self) -> String {
        format!("{}/v1", self.0)
    }

    /// 呼び出し側が対象Revisionと三IDの対応を照合してから渡す。
    pub fn fixed_citation(&self, knowledge: Id, genesis: Id, revision: Id) -> Option<Citation> {
        if (knowledge.kind, genesis.kind, revision.kind)
            != (Kind::Knowledge, Kind::Record, Kind::Record)
        {
            return None;
        }
        Some(Citation {
            reference: format!("lngnb:1:{knowledge}:{genesis}:{revision}"),
            url: format!("{}/view/{knowledge}/{genesis}/{revision}", self.0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_citation_uses_configured_origin_path_and_all_three_ids() {
        let base = PublicBaseUrl::parse("https://relay.example:8443/library").unwrap();
        let knowledge = Id {
            kind: Kind::Knowledge,
            bytes: [0; 32],
        };
        let genesis = Id {
            kind: Kind::Record,
            bytes: [0; 32],
        };
        let revision = Id {
            kind: Kind::Record,
            bytes: [0xff; 32],
        };
        let citation = base.fixed_citation(knowledge, genesis, revision).unwrap();
        let k = "kn1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let g = "rc1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let r = "rc1_777777777777777777777777777777777777777777777777777q";
        assert_eq!(citation.reference, format!("lngnb:1:{k}:{g}:{r}"));
        assert_eq!(
            citation.url,
            format!("https://relay.example:8443/library/view/{k}/{g}/{r}")
        );
        assert_eq!(base.api_base_url(), "https://relay.example:8443/library/v1");
        assert!(base.fixed_citation(genesis, genesis, revision).is_none());
    }

    #[test]
    fn public_base_url_rejects_ambiguous_or_noncanonical_input() {
        for valid in [
            "https://relay.example",
            "https://127.0.0.1",
            "https://[::1]:8443/a/b",
        ] {
            assert!(PublicBaseUrl::parse(valid).is_some(), "{valid}");
        }
        for invalid in [
            "http://relay.example",
            "https://user@relay.example",
            "https://relay.example.",
            "https://relay.example:0",
            "https://relay.example/",
            "https://relay.example/a//b",
            "https://relay.example/../b",
            "https://relay.example/%2e",
            "https://relay.example?q=a",
            "https://relay.example/a#x",
            "https://relay.example/a\\b",
            "https://0x7f000001",
            "https://0177.0.0.1",
            "https://127.1",
            "https://[fe80::1%eth0]",
        ] {
            assert!(PublicBaseUrl::parse(invalid).is_none(), "{invalid}");
        }
    }
}
