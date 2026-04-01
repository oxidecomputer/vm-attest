// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(feature = "test-data")]
use anyhow::Context;
use anyhow::Result;

#[cfg(feature = "test-data")]
mod test_data;

fn main() -> Result<()> {
    #[cfg(feature = "test-data")]
    test_data::generate().context("generate mock data for testing")?;

    Ok(())
}
