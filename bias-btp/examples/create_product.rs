use std::env;
use std::path::PathBuf;
use std::time::Duration;

use bias_btp::{BTPClient, BTPCredentials};
use tokio::fs::File;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    dotenvy::dotenv().ok();

    let instance_slug = env::var("BTP_INSTANCE_SLUG").unwrap_or_else(|_| "qa.stage".to_owned());

    let client_id = env::var("BTP_CLIENT_ID").expect("BTP_CLIENT_ID environment variable required");
    let client_secret =
        env::var("BTP_CLIENT_SECRET").expect("BTP_CLIENT_SECRET environment variable required");

    let product_name =
        env::var("BTP_PRODUCT_NAME").expect("BTP_PRODUCT_NAME environment variable required");
    let product_description = env::var("BTP_PRODUCT_DESCRIPTION").ok();

    let image_name =
        env::var("BTP_IMAGE_NAME").expect("BTP_IMAGE_NAME environment variable required");
    let image_version =
        env::var("BTP_IMAGE_VERSION").expect("BTP_IMAGE_VERSION environment variable required");
    let image_path =
        env::var("BTP_IMAGE_PATH").expect("BTP_IMAGE_PATH environment variable required");

    let credentials = BTPCredentials::new_m2m(client_id, client_secret);

    let client = BTPClient::new(&instance_slug)?;
    client.authenticate(&credentials).await?;

    println!("Successfully authenticated!");

    let product = client
        .create_product(&product_name, product_description)
        .await?;

    println!("\nProduct created:");
    println!("  ID: {}", product.id());
    println!("  Name: {}", product.name());
    if let Some(desc) = product.description() {
        println!("  Description: {}", desc);
    }
    println!("  Created: {}", product.create_time());

    let path = PathBuf::from(&image_path);
    let file = File::open(&path).await?;
    let metadata = file.metadata().await?;
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("image.bin");

    println!(
        "\nUploading image: {} ({} bytes)",
        path.display(),
        metadata.len()
    );

    let (image, scan_id) = client
        .upload_and_scan_image(&product, &image_name, &image_version, filename, file)
        .await?;

    println!("\nImage uploaded:");
    println!("  ID: {}", image.id());
    println!("  Name: {}", image.name());
    println!("  Version: {}", image.version());
    println!("  Created: {}", image.create_time());
    println!("  Scan ID: {}", scan_id);

    println!("\nPolling scan until complete...");

    let scan = client
        .poll_scan_until_complete(product.id(), image.id(), scan_id, Duration::from_secs(5))
        .await?;

    println!("\nScan complete:");
    println!("  ID: {}", scan.id());
    println!("  State: {:?}", scan.state_type());
    println!("  Created: {}", scan.create_time());

    Ok(())
}
