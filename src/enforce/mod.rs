use crate::events::ObservedEvent;
use crate::policy::Decision;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementOutcome {
    pub decision: Decision,
    pub blocked_event: Option<ObservedEvent>,
}
