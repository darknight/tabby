use anyhow::Result;
use tokio_cron_scheduler::Job;
use tracing::error;

use crate::service::db::DbConn;

pub(crate) async fn refresh_token_async(db_conn: DbConn) -> Result<Job> {
    // job is run every 2 hours
    let job = Job::new_async("0 0 1/2 * * * *", move |_, _| {
        let db_conn = db_conn.clone();
        Box::pin(async move {
            let res = db_conn.delete_expired_token().await;
            if let Err(e) = res {
                error!("failed to delete expired token: {}", e);
            }
        })
    })?;

    Ok(job)
}

macro_rules! repository_job {
    ($name:literal, $interval:expr) => {{
        tokio_cron_scheduler::Job::new_repeated(std::time::Duration::from_secs($interval), |_, _| {
            use tabby_common::schema::SchedulerRunMeta;
            use crate::path::cron_job_runs_dir;

            let start_time = chrono::Utc::now();

            let exe = std::env::current_exe().unwrap();
            let mut cmd = std::process::Command::new(exe);
            cmd.args(["scheduler::job", "--run", $name]);

            // run command as a child process
            let output = cmd.output();
            let Ok(output) = output else {
                error!("job `{}` failed: {:?}", $name, output.unwrap_err());
                return;
            };
            let finish_time = chrono::Utc::now();

            // prepare directory
            let this_run_dir = cron_job_runs_dir().join($name).join(
                format!("run_{}", start_time.format("%Y-%m-%d-%H-%M-%S").to_string())
            );
            std::fs::create_dir_all(&this_run_dir).unwrap();

            let meta = SchedulerRunMeta {
                start_time,
                finish_time,
                success: output.status.success(),
            };
            // write files
            std::fs::write(
                this_run_dir.join("meta.json"),
                serde_json::to_string(&meta).unwrap(),
            ).unwrap();
            std::fs::write(this_run_dir.join("stdout"), output.stdout).unwrap();
            std::fs::write(this_run_dir.join("stderr"), output.stderr).unwrap();
        })
    }};
}
