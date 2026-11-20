//! Record本体の公開可否。仕様 §7.2.2。状態案内、候補一覧、本文には別の条件がある。

use super::Validation;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PublicationPermission {
    #[default]
    None,
    Public,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationAnchor {
    Pinned,
    Untrusted,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DistributionGate {
    #[default]
    Closed,
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordPublication {
    Private,
    Public,
    UntrustedPublic,
}

impl RecordPublication {
    /// 同じ対象の確定済み許可・現在評価・起点を使う。
    /// 現在評価が未確定または未対応なら validation は None。
    /// 手動確認待ち、起動未完了、配信停止、縮小未確定の間は gate を閉じる。
    pub fn assess(
        permission: PublicationPermission,
        validation: Option<Validation>,
        anchor: PublicationAnchor,
        explicitly_stopped: bool,
        gate: DistributionGate,
    ) -> Self {
        if gate == DistributionGate::Closed
            || explicitly_stopped
            || validation != Some(Validation::Valid)
        {
            return Self::Private;
        }

        match (permission, anchor) {
            (PublicationPermission::Public, PublicationAnchor::Pinned) => Self::Public,
            (PublicationPermission::Untrusted, PublicationAnchor::Untrusted) => {
                Self::UntrustedPublic
            }
            _ => Self::Private,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_and_anchor_must_match() {
        use PublicationAnchor::{Pinned, Unknown, Untrusted};
        use RecordPublication::{Private, Public, UntrustedPublic};

        for (permission, expected) in [
            (
                PublicationPermission::default(),
                [Private, Private, Private],
            ),
            (PublicationPermission::Public, [Public, Private, Private]),
            (
                PublicationPermission::Untrusted,
                [Private, UntrustedPublic, Private],
            ),
        ] {
            for (anchor, expected) in [Pinned, Untrusted, Unknown].into_iter().zip(expected) {
                assert_eq!(
                    RecordPublication::assess(
                        permission,
                        Some(Validation::Valid),
                        anchor,
                        false,
                        DistributionGate::Open,
                    ),
                    expected,
                );
            }
        }
    }

    #[test]
    fn either_publication_route_denies_stopped_or_unverified_records() {
        for (permission, anchor) in [
            (PublicationPermission::Public, PublicationAnchor::Pinned),
            (
                PublicationPermission::Untrusted,
                PublicationAnchor::Untrusted,
            ),
        ] {
            for (validation, explicitly_stopped, gate) in [
                (Some(Validation::Valid), false, DistributionGate::default()),
                (Some(Validation::Valid), true, DistributionGate::Open),
                (Some(Validation::Pending), false, DistributionGate::Open),
                (Some(Validation::Invalid), false, DistributionGate::Open),
                (None, false, DistributionGate::Open),
            ] {
                assert_eq!(
                    RecordPublication::assess(
                        permission,
                        validation,
                        anchor,
                        explicitly_stopped,
                        gate
                    ),
                    RecordPublication::Private,
                );
            }
        }
    }
}
