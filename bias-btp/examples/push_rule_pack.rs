use std::env;

use bias_btp::{BTPClient, BTPCredentials, BTPError, BTPRulePackBuilder, BTPRulePlatform};

const RULE: &str = r#"author = "Binarly"
name = "CVE-2025-4421"
platform = "efi-module"
architecture = "X86:LE:64"
conditions = {
  platform = {volume_guids = {"caa3fa1c-76c4-44ce-bec0-3e6d847af8d4"}}
}

scopes = {scope:project{with = check}}

local function check(project)
  local x86 = require "uefi/primitives/x86"

  local pattern1 = project:search_code(
                     "8975..8975..488975..8975..488975..488975..408875..ff10488d45..4c8bcf48894424..448d46..488b05........418bd4488bc8ff10488d45..4c8bcf48894424..448d46..488b05........418bd4488bc8ff10488d45..4c8bcf48894424..448d46..488b05........418bd4488bc8ff10488d45..4c8bcf48894424..448d46..488b05........418bd4488b
c8ff10817d..........74..48b8................e9")

  if pattern1 == nil then
    pattern1 = project:search_code(
                 "448975..448975..4c8975..448975..4c8975..448875..ff10488d45..4c8bce48894424..458d46..488b05........8bd7488bc8ff10488d45..4c8bce48894424..458d46..488b05........8bd7488bc8ff10488d45..4c8bce48894424..458d46..488b05........8bd7488bc8ff10488d45..4c8bce48894424..458d46..488b05........8bd7488bc8ff10817d....
......74..48b8................e9")
  end

  if pattern1 == nil then
    pattern1 = project:search_code(
                 "8975..8975..488975..8975..488975..488975..408875..ff10488d45..4c8bcf48894424..448d46..488b05........418bd5488bc8ff10488d45..4c8bcf48894424..448d46..488b05........418bd5488bc8ff10488d45..4c8bcf48894424..448d46..488b05........418bd5488bc8ff10488d45..4c8bcf48894424..448d46..488b05........418bd5488bc8ff
10817d..........74..48b8................e9")
  end

  if pattern1 == nil then return end

  local pattern2 = project:search_code("8b45..48b9................488908488d45")

  if pattern2 == nil then return end

  local function_address = pattern1.function_address
  local read_save_state = x86.find_last_call(pattern1)
  local write = pattern2.insns[1].address

  return result:high{
    name = "CVE-2025-4421",
    description = "Multiple SMM memory corruption vulnerabilities in SMM module on Lenovo device (SMRAM write)",
    cwes = {"CWE-787", "CWE-822"},
    cvss = cvss:v3_1{
      base = "8.2",
      exploitability = "1.5",
      impact = "6.0",
      vector = "AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"
    },
    identifiers = {"BRLY-DVA-2025-013", "CVE-2025-4421"},
    advisory = "https://www.binarly.io/advisories/brly-dva-2025-013",
    evidence = {
      functions = {
        [function_address] = {
          annotate:at{
            location = read_save_state,
            message = "This call to `gEfiSmmCpuProtocol->ReadSaveState` will initialise\n`Buffer` (the last parameter) with the pointer value specified in\n`EFI_SMM_SAVE_STATE_REGISTER_RSI`"
          }, annotate:at{
            location = write,
            message = "Arbitrary write to buffer pointed to by the value derived from `EFI_SMM_SAVE_STATE_REGISTER_RSI`"
          }
        }
      }
    }
  }
end"#;

#[tokio::main]
async fn main() -> Result<(), BTPError> {
    let instance_slug = env::var("BTP_INSTANCE_SLUG").unwrap_or_else(|_| "qa.stage".to_owned());

    let user = env::var("BTP_USERNAME").expect("BTP_USERNAME environment variable required");
    let pass = env::var("BTP_PASSWORD").expect("BTP_PASSWORD environment variable required");

    let client = BTPClient::new(instance_slug)?;
    client
        .authenticate(&BTPCredentials::new_user(user, pass))
        .await?;

    let builder = BTPRulePackBuilder::new("uefi-simple-cve-2025-4421", "v1.0")
        .with_annotation("org.opencontainers.image.description", "Example rule pack")
        .with_rule(BTPRulePlatform::Uefi, "example.vh", RULE)
        .await?;

    let digest = builder.push(&client).await?;
    println!("Pushed rule pack: {digest}");

    Ok(())
}
