use std::env;
use std::path::PathBuf;

use bias_btp::{BTPClient, BTPCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    dotenvy::dotenv().ok();

    let instance_slug = env::var("BTP_INSTANCE_SLUG").unwrap_or_else(|_| "qa.stage".to_owned());

    let client_id = env::var("BTP_CLIENT_ID").expect("BTP_CLIENT_ID environment variable required");
    let client_secret =
        env::var("BTP_CLIENT_SECRET").expect("BTP_CLIENT_SECRET environment variable required");
    let product_id =
        env::var("BTP_PRODUCT_ID").unwrap_or_else(|_| "01KGHVB2JVK6AE1XKT89FKKC21".to_owned());

    let image_id =
        env::var("BTP_IMAGE_ID").unwrap_or_else(|_| "01KGQ22SEX6JKWXPHMYEQ9NKE7".to_owned());

    let scan_id = std::env::var("BTP_SCAN_ID").ok();

    let credentials = BTPCredentials::new_m2m(client_id, client_secret);

    let client = BTPClient::new(&instance_slug)?;
    client.authenticate(&credentials).await?;

    let download_url = client
        .generate_download_url(&product_id, image_id.as_str(), scan_id.as_deref())
        .await?;

    println!("download URL: {download_url}");

    let filename = BTPClient::extract_filename_from_url(&download_url)
        .unwrap_or_else(|| PathBuf::from("output.ba2"));

    let output_path = PathBuf::from(&filename);
    let size = client
        .download_ba2_to_file(&download_url, &output_path)
        .await?;

    println!("downloaded {size} bytes to {}", filename.display());

    Ok(())
}
