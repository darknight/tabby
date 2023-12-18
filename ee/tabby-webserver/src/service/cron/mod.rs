use std::time::Duration;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::error;
use crate::service::db::DbConn;

#[macro_use]
pub mod job;
mod output;
pub use output::read_run_output;

async fn new_job_scheduler(jobs: Vec<Job>) -> anyhow::Result<JobScheduler> {
    let scheduler = JobScheduler::new().await?;
    for job in jobs {
        scheduler.add(job).await?;
    }
    scheduler.start().await?;
    Ok(scheduler)
}

pub fn run_offline_job_async(db_conn: DbConn) {
    tokio::spawn(async move {
        let Ok(job) = job::refresh_token_async(db_conn).await else {
            error!("failed to create db job");
            return;
        };

        let Ok(mut scheduler) = new_job_scheduler(vec![job]).await else {
            error!("failed to start job scheduler for async job");
            return;
        };

        loop {
            match scheduler.time_till_next_job().await {
                Ok(Some(duration)) => {
                    tokio::time::sleep(duration).await;
                }
                Ok(None) => {
                    // wait until scheduler increases jobs' tick
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(e) => {
                    error!("failed to get job sleep time: {}, re-try in 1 second", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });
}

pub fn run_offline_job() {
    tokio::task::spawn(async {
        // run every 5 minutes
        let Ok(job1) = repository_job!("sync-repository", 5 * 60) else {
            error!("failed to create sync-repository job");
            return;
        };
        // run every 5 hours
        let Ok(job2) = repository_job!("index-repository", 5 * 60 * 60) else {
            error!("failed to create index-repository job");
            return;
        };

        let Ok(mut scheduler) = new_job_scheduler(vec![job1, job2]).await else {
            error!("failed to start job scheduler");
            return;
        };

        loop {
            match scheduler.time_till_next_job().await {
                Ok(Some(duration)) => {
                    tokio::time::sleep(duration).await;
                }
                Ok(None) => {
                    // wait until scheduler increases jobs' tick
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(e) => {
                    error!("failed to get job sleep time: {}, re-try in 1 second", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });
}
