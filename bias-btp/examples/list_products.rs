use std::env;

use bias_btp::{BTPClient, BTPCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    dotenvy::dotenv().ok();

    let instance_slug = env::var("BTP_INSTANCE_SLUG").unwrap_or_else(|_| "qa.stage".to_owned());

    let client_id = env::var("BTP_CLIENT_ID").expect("BTP_CLIENT_ID environment variable required");
    let client_secret =
        env::var("BTP_CLIENT_SECRET").expect("BTP_CLIENT_SECRET environment variable required");

    let credentials = BTPCredentials::new_m2m(client_id, client_secret);

    let client = BTPClient::new(&instance_slug)?;
    client.authenticate(&credentials).await?;

    println!("Successfully authenticated!");

    let products = client.list_products().await?;
    println!("\nProducts ({}):", products.len());
    for product in &products {
        println!("  {} - {}", product.id(), product.name());
        if let Some(desc) = product.description() {
            println!("    Description: {}", desc);
        }
    }

    Ok(())
}
