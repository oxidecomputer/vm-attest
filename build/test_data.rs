// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use anyhow::{Context, anyhow};
use attest_mock::{MockCorim, MockData, MockLog};
use camino::Utf8PathBuf;
use pki_playground::{OutputFileExistsBehavior, config};
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

fn write_path_to_conf<P: AsRef<Path>>(
    mut file: &File,
    path: P,
    name: &str,
) -> Result<()> {
    let path = path.as_ref();

    if !fs::exists(path).with_context(|| {
        format!("checking existance of file: {}", path.display())
    })? {
        return Err(anyhow!("required file not present: {}", path.display()));
    }

    Ok(writeln!(
        file,
        "#[allow(dead_code)]\npub const {}: &str =\n    \"{}\";\n",
        name,
        path.display(),
    )?)
}

fn mock_data<R: MockData, P: AsRef<Path>>(input: P, output: P) -> Result<()>
where
    <R as MockData>::Error: std::error::Error + Send + Sync + 'static,
{
    let input = input.as_ref();
    let output = output.as_ref();

    let mock = R::load(input)?;
    let log = mock.to_bytes()?;
    Ok(std::fs::write(output, &log).with_context(|| {
        format!("write mock measurement log to file: {}", output.display())
    })?)
}

pub fn generate() -> Result<()> {
    // output directory where we put generated test inputs
    let mut out =
        PathBuf::from(env::var("OUT_DIR").context("Could not get OUT_DIR")?);

    // paths consumed by the library as const `&str`s go here
    out.push("config.rs");
    let config_out = File::create(&out)
        .with_context(|| format!("creating {}", out.display()))?;
    out.pop();

    // directory hosting test input data
    let mut test_data = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .context("Failed to get CARGO_MANIFEST_DIR")?,
    );
    test_data.push("test-data");

    // load pki-playground config
    test_data.push("config.kdl");
    let tmp = Utf8PathBuf::try_from(test_data.clone())
        .context("limit path to UTF8 character set for pki-playground")?;
    let doc = config::load_and_validate(&tmp).map_err(|e| {
        anyhow!(
            "Load pki-playground config from \"{}\" failed: {e:?}",
            test_data.display()
        )
    })?;
    test_data.pop();

    // generate keys & record the path to `alias` key for the tests mocking an
    // attestation signer
    doc.write_key_pairs(&out, OutputFileExistsBehavior::Skip)
        .map_err(|e| anyhow!("writing key pairs failed: {e:?}"))?;
    out.push("test-alias.key.pem");
    write_path_to_conf(&config_out, &out, "ATTESTATION_SIGNER")
        .context("write variable w/ path to attestation signing key")?;
    out.pop();

    // generate certs & record the path to the PKI root cert for tests that
    // validate the cert chain
    doc.write_certificates(&out, OutputFileExistsBehavior::Skip)
        .map_err(|e| anyhow!("writing certificates failed: {e:?}"))?;
    out.push("test-root.cert.pem");
    write_path_to_conf(&config_out, &out, "PKI_ROOT")
        .context("write PKI_ROOT const str to config.rs")?;
    out.pop();

    // generate cert chains & record the path to the attestation signer cert
    // chain
    doc.write_certificate_lists(&out, OutputFileExistsBehavior::Skip)
        .map_err(|e| anyhow!("writing certificate lists failed: {e:?}"))?;
    out.push("test-alias.certlist.pem");
    write_path_to_conf(&config_out, &out, "SIGNER_PKIPATH")
        .context("write variable w/ path to attestation signing key")?;
    out.pop();

    // generate measurement log & record its path
    test_data.push("log.kdl");
    out.push("log.bin");
    mock_data::<MockLog, _>(&test_data, &out)?;
    write_path_to_conf(&config_out, &out, "LOG")
        .context("write variable w/ path to attestation signing key")?;
    out.pop();
    test_data.pop();

    // generate the corpus of reference measurements & record its path
    test_data.push("corim.kdl");
    out.push("corim.cbor");
    mock_data::<MockCorim, _>(&test_data, &out)?;
    write_path_to_conf(&config_out, &out, "CORIM").context(
        "write variable w/ path to reference integrity measurements",
    )?;
    test_data.pop();

    // record the path to the log used by the mock VmInstanceRot
    test_data.push("vm-instance-cfg.json");
    write_path_to_conf(&config_out, &test_data, "VM_INSTANCE_CFG").context(
        "write variable w/ path to data attested by the InstanceRoT",
    )?;

    Ok(())
}
