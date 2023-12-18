use crate::path::cron_job_runs_dir;
use tokio::fs;
use tabby_common::schema::SchedulerRunMeta;
use crate::schema::SchedulerRunOutput;
use anyhow::Result;

/// Load the output of a cron job run.
pub async fn read_run_output(
    job_name: &str,
    offset: usize,
    limit: usize,
    oldest_first: bool
) -> Result<Vec<SchedulerRunOutput>> {
    let job_runs_root = cron_job_runs_dir().join(job_name);
    if !fs::metadata(&job_runs_root).await.ok().map(|m| m.is_dir()).unwrap_or_default() {
        return Ok(Vec::new());
    }

    let mut entries = fs::read_dir(&job_runs_root).await?;
    let mut run_paths = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        run_paths.push(entry.path())
    }

    run_paths.sort();
    if !oldest_first {
        run_paths.reverse();
    }

    let mut runs = Vec::new();
    for run_dir in run_paths.iter().skip(offset).take(limit) {
        let meta_path = run_dir.join("meta.json");
        let meta = serde_json::from_str::<SchedulerRunMeta>(&fs::read_to_string(meta_path).await?)?;
        let stdout_path = run_dir.join("stdout");
        let stdout = fs::read_to_string(stdout_path).await?;
        let stderr_path = run_dir.join("stderr");
        let stderr = fs::read_to_string(stderr_path).await?;

        let run_id = run_dir.file_name().unwrap().to_str().unwrap().to_owned();
        runs.push(SchedulerRunOutput {
            run_id,
            meta: meta.into(),
            stdout,
            stderr,
            total_runs: run_paths.len() as i32,
        });
    }

    Ok(runs)
}
