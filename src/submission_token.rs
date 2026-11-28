//! Restricted投稿の内部認証。呼出側は同一受付スナップショットの台帳を照合する。
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn verifier(raw: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"lngnb:submission-token:1\0");
    hash.update(raw);
    hash.finalize().into()
}

/// 発行時だけ返すBearer値と、台帳用の一方向照合値。
pub fn issue() -> Result<(Zeroizing<String>, [u8; 32]), getrandom::Error> {
    let mut raw = Zeroizing::new([0; 32]);
    getrandom::getrandom(&mut *raw)?;
    let mut bearer = Zeroizing::new(String::from("pt1_"));
    let mut encoded = Zeroizing::new(BASE32_NOPAD.encode(&*raw));
    encoded.make_ascii_lowercase();
    bearer.push_str(&encoded);
    Ok((bearer, verifier(&raw)))
}

fn parse(bearer: &str) -> Option<[u8; 32]> {
    let payload = bearer.strip_prefix("pt1_")?;
    if payload.len() != 52
        || !payload
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        return None;
    }
    let encoded = Zeroizing::new(payload.to_ascii_uppercase());
    let mut raw = Zeroizing::new([0; 32]);
    BASE32_NOPAD
        .decode_mut(encoded.as_bytes(), &mut *raw)
        .ok()?;
    Some(verifier(&raw))
}

pub struct Policy {
    pub revoked: bool,
    pub expires_at: Option<u64>,
    /// Noneは範囲制限なし。空集合はすべて拒否する。
    pub knowledge: Option<Vec<[u8; 32]>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Denial {
    Unauthorized,
    Forbidden,
}

/// targetは検査済みRecordから得たKnowledge ID、またはBlob投稿の指定値。
/// 外側のResultで台帳の読取り障害を呼出側に返す。
pub fn authorize<E>(
    bearer: &str,
    now: u64,
    target: Option<[u8; 32]>,
    lookup: impl FnOnce([u8; 32]) -> Result<Option<Policy>, E>,
) -> Result<Result<(), Denial>, E> {
    let Some(key) = parse(bearer) else {
        return Ok(Err(Denial::Unauthorized));
    };
    let Some(policy) = lookup(key)? else {
        return Ok(Err(Denial::Unauthorized));
    };
    if policy.revoked || policy.expires_at.is_some_and(|end| now >= end) {
        return Ok(Err(Denial::Unauthorized));
    }
    if let Some(scope) = policy.knowledge {
        if !target.is_some_and(|id| scope.contains(&id)) {
            return Ok(Err(Denial::Forbidden));
        }
    }
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_token_and_domain() {
        // 公開試験値。運用には使用しない。
        let token = format!("pt1_{}", "a".repeat(52));
        let digest = parse(&token).unwrap();
        assert_eq!(
            data_encoding::HEXLOWER.encode(&digest),
            "6a2e6f954d82e39d5a474e57bbc6b822c28431c2dcad7130aa987113e5935861"
        );
        for bad in [
            token.to_uppercase(),
            format!("{}b", &token[..55]),
            token[1..].into(),
        ] {
            assert!(parse(&bad).is_none());
        }
        let (issued, digest) = issue().unwrap();
        assert_eq!(parse(&issued), Some(digest));
    }

    #[test]
    fn authentication_precedes_knowledge_scope() {
        let (token, digest) = issue().unwrap();
        let check = |revoked, expires_at, knowledge, target| {
            authorize(&token, 10, target, |key| {
                assert_eq!(key, digest);
                Ok::<_, ()>(Some(Policy {
                    revoked,
                    expires_at,
                    knowledge,
                }))
            })
            .unwrap()
        };
        let id = [1; 32];
        assert_eq!(check(false, Some(11), Some(vec![id]), Some(id)), Ok(()));
        assert_eq!(check(false, None, None, None), Ok(()));
        for target in [None, Some([2; 32])] {
            assert_eq!(
                check(false, None, Some(vec![id]), target),
                Err(Denial::Forbidden)
            );
        }
        assert_eq!(
            check(false, None, Some(vec![]), Some(id)),
            Err(Denial::Forbidden)
        );
        for (revoked, end) in [(true, None), (false, Some(10)), (false, Some(9))] {
            assert_eq!(
                check(revoked, end, Some(vec![]), None),
                Err(Denial::Unauthorized)
            );
        }
        assert_eq!(
            authorize(&token, 10, None, |_| Ok::<_, ()>(None)),
            Ok(Err(Denial::Unauthorized))
        );
        assert_eq!(
            authorize(&token, 10, None, |_| Err("storage")),
            Err("storage")
        );
    }
}
