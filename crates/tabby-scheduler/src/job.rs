use tracing::error;
use tabby_common::config::Config;
use crate::{dataset, index, repository};

pub(crate) fn sync_repository(config: &Config) {
    println!("Syncing repositories...");
    let ret = repository::sync_repositories(&config);
    if let Err(err) = ret {
        error!("Failed to sync repositories, err: '{}'", err);
        return;
    }

    println!("Building dataset...");
    let ret = dataset::create_dataset(&config);
    if let Err(err) = ret {
        error!("Failed to build dataset, err: '{}'", err);
    }
    println!();
}

pub(crate) fn index_repository(config: &Config) {
    println!("Indexing repositories...");
    let ret = index::index_repositories(&config);
    if let Err(err) = ret {
        error!("Failed to index repositories, err: '{}'", err);
    }
    println!();
}
