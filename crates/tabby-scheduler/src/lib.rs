mod dataset;
mod index;
mod repository;
mod utils;
mod job;

use anyhow::Result;
use job_scheduler::{Job, JobScheduler};
use tabby_common::config::Config;
use tabby_common;
use tracing::{error, info};

pub async fn scheduler(now: bool) -> Result<()> {
    let config = Config::load()?;
    let mut scheduler = JobScheduler::new();

    let job1 = || {
        job::sync_repository(&config);
    };

    let job2 = || {
        job::index_repository(&config);
    };

    if now {
        job1();
        job2();
    } else {
        // Every 5 minutes.
        scheduler.add(Job::new("0 1/5 * * * * *".parse().unwrap(), job1));

        // Every 5 hours.
        scheduler.add(Job::new("0 0 1/5 * * * *".parse().unwrap(), job2));

        info!("Scheduler activated...");
        loop {
            scheduler.tick();
            let duration = scheduler.time_till_next_job();
            info!("Sleep {:?} for next job ...", duration);
            std::thread::sleep(duration);
        }
    }

    Ok(())
}

#[cfg(feature = "ee")]
pub fn scheduler_job(job: String) {
    let Ok(config) = Config::load() else {
        error!("Scheduler job failed to load config");
        return;
    };
    match job.as_str() {
        "sync-repository" => {
            job::sync_repository(&config)
        },
        "index-repository" => {
            job::index_repository(&config)
        },
        _ => error!("Unknown job: {}", job),
    }
}
