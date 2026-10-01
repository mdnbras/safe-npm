use anyhow::{bail, Context, Result};
use semver::{Version, VersionReq};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct PackageArtifact {
    pub name: String,
    pub version: String,
    pub tarball_url: String,
    pub dependencies: BTreeMap<String, String>,
}

pub struct RegistryClient {
    client: reqwest::blocking::Client,
}

impl RegistryClient {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .user_agent(concat!("safe-npm/", env!("CARGO_PKG_VERSION")))
                .build()?,
        })
    }

    pub fn resolve(&self, spec: &str) -> Result<PackageArtifact> {
        let (name, requested) = split_spec(spec)?;
        self.resolve_name_range(&name, requested.as_deref())
    }

    pub fn resolve_name_range(&self, name: &str, requested: Option<&str>) -> Result<PackageArtifact> {
        let metadata = self.metadata(name)?;
        let version = resolve_version(&metadata, requested)
            .with_context(|| format!("could not resolve {name} {}", requested.unwrap_or("latest")))?;
        let data = &metadata["versions"][&version];
        let tarball_url = data["dist"]["tarball"].as_str()
            .context("package version has no tarball URL")?.to_owned();
        let dependencies = data["dependencies"].as_object()
            .map(|o| o.iter().filter_map(|(k,v)| v.as_str().map(|s|(k.clone(),s.to_owned()))).collect())
            .unwrap_or_default();
        Ok(PackageArtifact { name: name.to_owned(), version, tarball_url, dependencies })
    }

    pub fn download(&self, artifact: &PackageArtifact) -> Result<Vec<u8>> {
        Ok(self.client.get(&artifact.tarball_url).send()
            .context("failed to download package tarball")?
            .error_for_status()?.bytes()?.to_vec())
    }

    fn metadata(&self, name: &str) -> Result<Value> {
        let encoded = urlencoding::encode(name);
        Ok(self.client.get(format!("https://registry.npmjs.org/{encoded}")).send()
            .context("failed to query npm registry")?
            .error_for_status().context("npm registry returned an error")?
            .json().context("invalid npm registry metadata")?)
    }
}

fn resolve_version(metadata: &Value, requested: Option<&str>) -> Option<String> {
    let requested = requested.unwrap_or("latest");
    if let Some(tag) = metadata["dist-tags"][requested].as_str() { return Some(tag.to_owned()); }
    if metadata["versions"].get(requested).is_some() { return Some(requested.to_owned()); }
    let req = VersionReq::parse(requested).ok()?;
    metadata["versions"].as_object()?.keys()
        .filter_map(|v| Version::parse(v).ok())
        .filter(|v| req.matches(v))
        .max()
        .map(|v| v.to_string())
}

fn split_spec(spec: &str) -> Result<(String, Option<String>)> {
    if spec.trim().is_empty() { bail!("package name cannot be empty"); }
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
    use super::*;
    #[test]
    fn parses_specs() {
        assert_eq!(split_spec("lodash").unwrap(), ("lodash".into(), None));
        assert_eq!(split_spec("@scope/pkg@1.2.3").unwrap(), ("@scope/pkg".into(), Some("1.2.3".into())));
    }
    #[test]
    fn resolves_semver_range() {
        let v: Value = serde_json::from_str(r#"{"dist-tags":{"latest":"2.0.0"},"versions":{"1.0.0":{},"1.9.0":{},"2.0.0":{}}}"#).unwrap();
        assert_eq!(resolve_version(&v, Some("^1.0.0")).unwrap(), "1.9.0");
    }
}
