use std::fs;
use std::path::PathBuf;
use anyhow::{anyhow, Error};
use directories::ProjectDirs;

pub(crate) fn config_dir() -> Result<PathBuf, Error> {
    if let Some(proj_dirs) = ProjectDirs::from("", "SkyTemple",  "pelipper-post-office") {
        fs::create_dir(proj_dirs.config_dir()).ok();
        Ok(proj_dirs.config_dir().to_path_buf())
    } else {
        Err(anyhow!("Could not access config dirs"))
    }
}
