use anyhow::{bail, Context, Result};
use serde_json::Value;

pub struct ResolvedPackage {
    pub name: String,
    pub version: String,
    pub tarball: Vec<u8>,
}

pub fn fetch_package(spec: &str) -> Result<ResolvedPackage> {
    let (name, requested_version) = split_spec(spec)?;
    let encoded = urlencoding::encode(&name);
    let metadata_url = format!("https://registry.npmjs.org/{encoded}");
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("safe-npm/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let metadata: Value = client
        .get(&metadata_url)
        .send()
        .context("failed to query npm registry")?
        .error_for_status()
        .context("npm registry returned an error")?
        .json()
        .context("invalid npm registry metadata")?;

    let version = requested_version
        .or_else(|| metadata["dist-tags"]["latest"].as_str().map(str::to_owned))
        .context("could not resolve package version")?;

    let tarball_url = metadata["versions"][&version]["dist"]["tarball"]
        .as_str()
        .context("package version has no tarball URL")?;

    let tarball = client
        .get(tarball_url)
        .send()
        .context("failed to download package tarball")?
        .error_for_status()?
        .bytes()?
        .to_vec();

    Ok(ResolvedPackage { name, version, tarball })
}

fn split_spec(spec: &str) -> Result<(String, Option<String>)> {
    if spec.trim().is_empty() {
        bail!("package name cannot be empty");
    }

    if spec.starts_with('@') {
        if let Some(pos) = spec.rfind('@').filter(|p| *p > 0) {
            return Ok((spec[..pos].to_owned(), Some(spec[pos + 1..].to_owned())));
        }
        return Ok((spec.to_owned(), None));
    }

    match spec.rsplit_once('@') {
        Some((name, version)) if !name.is_empty() && !version.is_empty() =>
            Ok((name.to_owned(), Some(version.to_owned()))),
        _ => Ok((spec.to_owned(), None)),
    }
}

#[cfg(test)]
mod tests {
    use super::split_spec;

    #[test]
    fn parses_specs() {
        assert_eq!(split_spec("lodash").unwrap(), ("lodash".into(), None));
        assert_eq!(split_spec("lodash@4.17.21").unwrap(), ("lodash".into(), Some("4.17.21".into())));
        assert_eq!(split_spec("@scope/pkg").unwrap(), ("@scope/pkg".into(), None));
        assert_eq!(split_spec("@scope/pkg@1.2.3").unwrap(), ("@scope/pkg".into(), Some("1.2.3".into())));
    }
}
