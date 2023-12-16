use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SchedulerRunMeta {
    pub start_time: DateTime<Utc>,
    pub finish_time: DateTime<Utc>,
    pub success: bool,
}
