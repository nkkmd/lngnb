//! 既存の補助endpoint作成資格を共有する、明示的な追跡付き作成。
use super::*;

enum Auxiliary {
    Status,
    Evaluation(u64),
    Configuration,
}
impl Auxiliary {
    fn name(&self) -> &'static str {
        match self {
            Self::Status => status::NAME,
            Self::Evaluation(_) => evaluation::NAME,
            Self::Configuration => configuration::NAME,
        }
    }
}

pub(super) fn known_name(name: &str) -> bool {
    matches!(
        name,
        NAME | status::NAME | evaluation::NAME | configuration::NAME
    )
}

impl Listener {
    /// 新規status作成だけを追跡する。失敗時はListenerを返さず、名前/稼働中印を保全。
    /// 既存名の採用/整理・自動finishは行わない。elapsedは非保存の処理境界予算。
    pub fn enable_status_with_origin(
        self,
        elapsed: Duration,
    ) -> OriginResult<(Self, SocketOrigin)> {
        self.enable_auxiliary_origin(Auxiliary::Status, elapsed, |_| Ok(()))
    }
    /// 既存評価件数資格を検査して新規evaluation作成を追跡。失敗境界はstatusと同じ。
    pub fn enable_evaluation_with_origin(
        self,
        records: u64,
        elapsed: Duration,
    ) -> OriginResult<(Self, SocketOrigin)> {
        self.enable_auxiliary_origin(Auxiliary::Evaluation(records), elapsed, |_| Ok(()))
    }
    /// status/evaluationを用意済みのwriterへ新規configuration作成を追跡。
    pub fn enable_configuration_with_origin(
        self,
        elapsed: Duration,
    ) -> OriginResult<(Self, SocketOrigin)> {
        self.enable_auxiliary_origin(Auxiliary::Configuration, elapsed, |_| Ok(()))
    }

    fn enable_auxiliary_origin(
        mut self,
        target: Auxiliary,
        elapsed: Duration,
        after_bind: impl FnOnce(&Self) -> OriginResult<()>,
    ) -> OriginResult<(Self, SocketOrigin)> {
        let budget = Budget {
            start: Instant::now(),
            elapsed,
        };
        budget.check()?;
        let context = Context::read()?;
        budget.check()?;
        let name = target.name();
        match target {
            Auxiliary::Status => self.enable_status(),
            Auxiliary::Evaluation(records) => self.enable_evaluation_with_record_limit(records),
            Auxiliary::Configuration => self.enable_configuration(),
        }
        .map_err(SocketOriginError::Bind)?;
        after_bind(&self)?;
        let identity = self.observe_origin(name, &context.identity, &budget, || Ok(()))?;
        Ok((
            self,
            SocketOrigin {
                identity,
                namespace: context.namespace,
            },
        ))
    }

    pub(super) fn origin_socket(
        &self,
        name: &'static str,
    ) -> OriginResult<(&UnixListener, (u64, u64))> {
        if !known_name(name) {
            return Err(SocketOriginError::Mismatch);
        }
        self.check_endpoint()
            .map_err(|_| SocketOriginError::Mismatch)?;
        if name == NAME {
            return Ok((&self.socket, self.identity));
        }
        let endpoint = match name {
            status::NAME => &self.status,
            evaluation::NAME => &self.evaluation,
            configuration::NAME => &self.configuration,
            _ => return Err(SocketOriginError::Mismatch),
        }
        .as_ref()
        .ok_or(SocketOriginError::Mismatch)?;
        endpoint
            .check(self.access.store(), self.owner)
            .map_err(|_| SocketOriginError::Mismatch)?;
        Ok(endpoint.origin_parts())
    }
}

#[cfg(test)]
mod tests;
