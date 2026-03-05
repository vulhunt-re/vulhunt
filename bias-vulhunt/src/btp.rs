use std::path::{Path, PathBuf};

use bias_btp::{BTPClient, BTPCredentials, BTPRulePackBuilder, BTPRulePlatform, Ulid};

use clap::{Arg, ArgMatches, Command};
use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "status")]
pub enum BTPResponse<T>
where
    T: Serialize,
{
    #[serde(rename = "ok")]
    Ok { payload: T },
    #[serde(rename = "error")]
    Error { message: String },
}

impl<T> BTPResponse<T>
where
    T: Serialize,
{
    pub fn ok(payload: T) -> Self {
        Self::Ok { payload }
    }
}

impl BTPResponse<()> {
    pub fn error(message: impl Into<String>) -> Self {
        BTPResponse::Error {
            message: message.into(),
        }
    }
}

#[derive(Serialize)]
struct PushRulesPayload<'a> {
    repository: &'a str,
    tag: &'a str,
    manifest_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    deployed_to_product: Option<Ulid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deployed_to_org: Option<Ulid>,
}

#[derive(Serialize)]
struct CreateProductPayload {
    id: Ulid,
    name: String,
    description: Option<String>,
}

#[derive(Serialize)]
struct UploadImagePayload {
    image_id: Ulid,
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_id: Option<Ulid>,
}

#[derive(Serialize)]
struct DownloadBA2Payload {
    path: PathBuf,
    size: u64,
}

fn common_args(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("username")
            .short('u')
            .long("username")
            .env("BTP_USERNAME")
            .help("BTP username")
            .required(true),
    )
    .arg(
        Arg::new("password")
            .short('p')
            .long("password")
            .env("BTP_PASSWORD")
            .help("BTP password")
            .required(true),
    )
    .arg(
        Arg::new("instance-slug")
            .short('s')
            .long("instance-slug")
            .env("BTP_INSTANCE_SLUG")
            .help("Instance slug (e.g., \"your-org.prod\")")
            .required(true),
    )
}

fn push_rules_command() -> Command {
    common_args(Command::new("push-rules").about("Push a VulHunt rule pack to a BTP instance"))
        .arg(
            Arg::new("repository")
                .short('r')
                .long("repository")
                .help("Repository name (e.g., \"rulepacks/custom\")")
                .required(true),
        )
        .arg(
            Arg::new("tag")
                .short('t')
                .long("tag")
                .help("Image tag")
                .default_value("latest"),
        )
        .arg(
            Arg::new("deploy-to-product")
                .long("deploy-to-product")
                .help("Deploy rule pack to a product (ULID)")
                .value_parser(clap::value_parser!(Ulid))
                .conflicts_with("deploy-to-org"),
        )
        .arg(
            Arg::new("deploy-to-org")
                .long("deploy-to-org")
                .help("Deploy rule pack to an organisation (ULID)")
                .value_parser(clap::value_parser!(Ulid))
                .conflicts_with("deploy-to-product"),
        )
        .arg(Arg::new("name").long("name").help("Rule pack name"))
        .arg(
            Arg::new("platform")
                .long("platform")
                .help("Platform for individual .vh files (posix|uefi)")
                .value_parser(clap::value_parser!(BTPRulePlatform)),
        )
        .arg(
            Arg::new("modules")
                .long("modules")
                .help("Directory containing modules (.vhm files)")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("INPUTS")
                .help("Rule directories (named posix/ or uefi/) or individual .vh files")
                .num_args(1..)
                .required(true)
                .value_parser(clap::value_parser!(PathBuf)),
        )
}

/*
fn list_orgs_command() -> Command {
    common_args(Command::new("list-orgs").about("List organisations in a BTP instance"))
}
*/

fn list_products_command() -> Command {
    common_args(Command::new("list-products").about("List products in a BTP instance"))
}

fn create_product_command() -> Command {
    common_args(Command::new("create-product").about("Create a new product in a BTP instance"))
        .arg(
            Arg::new("name")
                .long("name")
                .help("Product name")
                .required(true),
        )
        .arg(
            Arg::new("description")
                .long("description")
                .help("Product description")
                .required(false),
        )
}

fn upload_command() -> Command {
    common_args(Command::new("upload").about("Upload an image/firmware file to a product"))
        .arg(
            Arg::new("product-id")
                .long("product-id")
                .help("Product ID (ULID)")
                .value_parser(clap::value_parser!(Ulid))
                .required(true),
        )
        .arg(
            Arg::new("name")
                .long("name")
                .help("Image name")
                .required(true),
        )
        .arg(
            Arg::new("version")
                .long("version")
                .help("Image version")
                .required(true),
        )
        .arg(
            Arg::new("scan")
                .long("scan")
                .help("Create a scan after upload")
                .num_args(0)
                .action(clap::ArgAction::SetTrue),
        )
        .arg(Arg::new("FILE").help("File to upload").required(true))
}

fn list_images_command() -> Command {
    common_args(Command::new("list-images").about("List images in a product")).arg(
        Arg::new("product-id")
            .long("product-id")
            .help("Product ID (ULID)")
            .value_parser(clap::value_parser!(Ulid))
            .required(true),
    )
}

fn list_scans_command() -> Command {
    common_args(Command::new("list-scans").about("List scans for an image"))
        .arg(
            Arg::new("product-id")
                .long("product-id")
                .help("Product ID (ULID)")
                .value_parser(clap::value_parser!(Ulid))
                .required(true),
        )
        .arg(
            Arg::new("image-id")
                .long("image-id")
                .help("Image ID (ULID)")
                .value_parser(clap::value_parser!(Ulid))
                .required(true),
        )
}

fn create_scan_command() -> Command {
    common_args(Command::new("create-scan").about("Create a scan for an existing image"))
        .arg(
            Arg::new("product-id")
                .long("product-id")
                .help("Product ID (ULID)")
                .value_parser(clap::value_parser!(Ulid))
                .required(true),
        )
        .arg(
            Arg::new("image-id")
                .long("image-id")
                .help("Image ID (ULID)")
                .value_parser(clap::value_parser!(Ulid))
                .required(true),
        )
}

fn get_scan_command() -> Command {
    common_args(Command::new("get-scan").about("Get details of an individual scan"))
        .arg(
            Arg::new("product-id")
                .long("product-id")
                .help("Product ID (ULID)")
                .value_parser(clap::value_parser!(Ulid))
                .required(true),
        )
        .arg(
            Arg::new("image-id")
                .long("image-id")
                .help("Image ID (ULID)")
                .value_parser(clap::value_parser!(Ulid))
                .required(true),
        )
        .arg(
            Arg::new("scan-id")
                .long("scan-id")
                .help("Scan ID (ULID)")
                .value_parser(clap::value_parser!(Ulid))
                .required(true),
        )
}

fn get_findings_command() -> Command {
    common_args(Command::new("get-findings").about("Get findings for an image"))
        .arg(
            Arg::new("product-id")
                .long("product-id")
                .help("Product ID (ULID)")
                .required(true)
                .value_parser(clap::value_parser!(Ulid)),
        )
        .arg(
            Arg::new("image-id")
                .long("image-id")
                .help("Image ID (ULID)")
                .required(true)
                .value_parser(clap::value_parser!(Ulid)),
        )
}

fn download_ba2_command() -> Command {
    common_args(
        Command::new("download-ba2").about("Download the BA2 file for a product/image from BTP"),
    )
    .arg(
        Arg::new("product-id")
            .long("product-id")
            .help("Product ID (ULID)")
            .required(true)
            .value_parser(clap::value_parser!(Ulid)),
    )
    .arg(
        Arg::new("image-id")
            .long("image-id")
            .help("Image ID (ULID)")
            .required(true)
            .value_parser(clap::value_parser!(Ulid)),
    )
    .arg(
        Arg::new("scan-id")
            .long("scan-id")
            .help("Scan ID (ULID)")
            .required(false)
            .value_parser(clap::value_parser!(Ulid)),
    )
    .arg(
        Arg::new("OUTPUT")
            .short('o')
            .long("output")
            .help("Output path (defaults to filename from URL)")
            .value_parser(clap::value_parser!(PathBuf)),
    )
}

pub fn command() -> Command {
    Command::new("btp")
        .about("Interact with the Binarly Transparency Platform (BTP)")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(push_rules_command())
        //.subcommand(list_orgs_command())
        .subcommand(list_products_command())
        .subcommand(create_product_command())
        .subcommand(upload_command())
        .subcommand(list_images_command())
        .subcommand(list_scans_command())
        .subcommand(create_scan_command())
        .subcommand(get_scan_command())
        .subcommand(get_findings_command())
        .subcommand(download_ba2_command())
}

async fn create_client(opts: &ArgMatches) -> Result<BTPClient, Box<dyn std::error::Error>> {
    let username = opts.get_one::<String>("username").unwrap();
    let password = opts.get_one::<String>("password").unwrap();
    let slug = opts.get_one::<String>("instance-slug").unwrap();

    let client = BTPClient::new(slug)?;
    client
        .authenticate(&BTPCredentials::new_user(
            username.clone(),
            password.clone(),
        ))
        .await?;

    Ok(client)
}

pub async fn run(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let result = match opts.subcommand() {
        Some(("push-rules", sub_m)) => run_push_rules(sub_m).await,
        // Some(("list-orgs", sub_m)) => run_list_orgs(sub_m).await,
        Some(("list-products", sub_m)) => run_list_products(sub_m).await,
        Some(("create-product", sub_m)) => run_create_product(sub_m).await,
        Some(("upload", sub_m)) => run_upload(sub_m).await,
        Some(("list-images", sub_m)) => run_list_images(sub_m).await,
        Some(("list-scans", sub_m)) => run_list_scans(sub_m).await,
        Some(("create-scan", sub_m)) => run_create_scan(sub_m).await,
        Some(("get-scan", sub_m)) => run_get_scan(sub_m).await,
        Some(("get-findings", sub_m)) => run_get_findings(sub_m).await,
        Some(("download-ba2", sub_m)) => run_download_ba2(sub_m).await,
        _ => unreachable!(),
    };

    if let Err(e) = result {
        let response = BTPResponse::error(e.to_string());
        serde_json::to_writer(std::io::stdout(), &response)?;
    }

    Ok(())
}

async fn run_push_rules(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client(opts).await?;

    let repository = opts.get_one::<String>("repository").unwrap();
    let tag = opts.get_one::<String>("tag").unwrap();
    let platform = opts.get_one::<BTPRulePlatform>("platform").copied();
    let modules_dir = opts.get_one::<PathBuf>("modules");
    let name = opts.get_one::<String>("name").cloned();
    let inputs = opts.get_many::<PathBuf>("INPUTS").unwrap();

    let mut builder = BTPRulePackBuilder::new(repository, tag);

    let name = name.as_deref().unwrap_or(".");
    builder.add_annotation("org.opencontainers.image.title", name);

    for input in inputs {
        if input.is_dir() {
            let dir_name = input
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();

            if let Some(p) = dir_name.parse::<BTPRulePlatform>().ok() {
                builder.add_rules_from_directory(p, input).await?;
            } else {
                tracing::warn!(
                    "skipping directory {}: not named posix/uefi and no --platform specified",
                    input.display()
                );
            }
        } else if input.extension().and_then(|e| e.to_str()) == Some("vh") {
            let p = platform.ok_or_else(|| {
                format!(
                    "must specify --platform for individual rule file: {}",
                    input.display()
                )
            })?;
            builder.add_rule_from_file(p, input).await?;
        }
    }

    if let Some(modules) = modules_dir {
        builder.add_modules_from_directory(modules).await?;
    }

    let manifest_url = builder.push(&client).await?;

    tracing::info!("pushed rule pack to {manifest_url}");

    let deploy_to_product = opts.get_one::<Ulid>("deploy-to-product").copied();
    let deploy_to_org = opts.get_one::<Ulid>("deploy-to-org").copied();

    let mut deployed_to_product = None;
    let mut deployed_to_org = None;

    if let Some(product_id) = deploy_to_product {
        client
            .update_product_rules_deployment(product_id, repository, tag, true)
            .await?;
        tracing::info!("deployed rule pack to product {product_id}");
        deployed_to_product = Some(product_id);
    } else if let Some(org_id) = deploy_to_org {
        client
            .update_org_rules_deployment(org_id, repository, tag, true)
            .await?;
        tracing::info!("deployed rule pack to organisation {org_id}");
        deployed_to_org = Some(org_id);
    }

    let payload = PushRulesPayload {
        repository,
        tag,
        manifest_url,
        deployed_to_product,
        deployed_to_org,
    };

    let response = BTPResponse::ok(payload);
    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

/*
async fn run_list_orgs(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client(opts).await?;
    let orgs = client.list_orgs().await?;

    let response = BTPResponse::ok(orgs);
    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}
*/

async fn run_list_products(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client(opts).await?;
    let products = client.list_products().await?;

    let response = BTPResponse::ok(products);
    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

async fn run_create_product(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client(opts).await?;

    let name = opts.get_one::<String>("name").unwrap().clone();
    let description = opts.get_one::<String>("description").cloned();

    let product = client.create_product(&name, description.as_deref()).await?;

    let payload = CreateProductPayload {
        id: product.id(),
        name: product.name().to_owned(),
        description,
    };

    let response = BTPResponse::ok(payload);
    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

async fn run_upload(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client(opts).await?;

    let product_id = *opts.get_one::<Ulid>("product-id").unwrap();
    let name = opts.get_one::<String>("name").unwrap().clone();
    let version = opts.get_one::<String>("version").unwrap().clone();
    let scan = opts.get_flag("scan");
    let file_path = opts.get_one::<String>("FILE").unwrap();

    let filename = Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(file_path)
        .to_owned();

    let file = tokio::fs::File::open(file_path).await?;

    let (image_id, scan_id) = if scan {
        let (image, scan_id) = client
            .upload_and_scan_image_by_id(product_id, &name, &version, &filename, file)
            .await?;
        (image.id(), Some(scan_id))
    } else {
        let image = client
            .upload_image_by_id(product_id, &name, &version, &filename, file)
            .await?;
        (image.id(), None)
    };

    let payload = UploadImagePayload {
        image_id,
        name,
        version,
        scan_id,
    };

    let response = BTPResponse::ok(payload);
    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

async fn run_list_images(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client(opts).await?;

    let product_id = *opts.get_one::<Ulid>("product-id").unwrap();
    let images = client.list_images_by_id(product_id).await?;

    let response = BTPResponse::ok(images);
    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

async fn run_list_scans(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client(opts).await?;

    let product_id = *opts.get_one::<Ulid>("product-id").unwrap();
    let image_id = *opts.get_one::<Ulid>("image-id").unwrap();
    let scans = client.list_scans(product_id, image_id).await?;

    let response = BTPResponse::ok(scans);
    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

async fn run_create_scan(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client(opts).await?;

    let product_id = *opts.get_one::<Ulid>("product-id").unwrap();
    let image_id = *opts.get_one::<Ulid>("image-id").unwrap();
    let scan = client.create_scan(product_id, image_id).await?;

    let response = BTPResponse::ok(scan);
    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

async fn run_get_scan(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client(opts).await?;

    let product_id = *opts.get_one::<Ulid>("product-id").unwrap();
    let image_id = *opts.get_one::<Ulid>("image-id").unwrap();
    let scan_id = *opts.get_one::<Ulid>("scan-id").unwrap();
    let scan = client.get_scan(product_id, image_id, scan_id).await?;

    let response = BTPResponse::ok(scan);
    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

async fn run_get_findings(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client(opts).await?;

    let product_id = *opts.get_one::<Ulid>("product-id").unwrap();
    let image_id = *opts.get_one::<Ulid>("image-id").unwrap();
    let findings = client.get_findings_report(product_id, image_id).await?;

    let response = BTPResponse::ok(findings);
    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

async fn run_download_ba2(opts: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let client = create_client(opts).await?;

    let product_id = opts.get_one::<Ulid>("product-id").unwrap();
    let image_id = opts.get_one::<Ulid>("image-id").unwrap();
    let scan_id = opts.get_one::<Ulid>("scan-id").copied();

    let product_id_str = product_id.to_string();
    let image_id_str = image_id.to_string();

    let url = client
        .generate_download_url(
            &product_id_str,
            image_id_str.as_str(),
            scan_id.map(|s| s.to_string()).as_deref(),
        )
        .await?;

    let path = match opts.get_one::<PathBuf>("OUTPUT") {
        Some(p) => p.clone(),
        None => BTPClient::extract_filename_from_url(&url)
            .unwrap_or_else(|| PathBuf::from("output.ba2")),
    };

    let size = client.download_ba2_to_file(&url, &path).await?;

    let payload = DownloadBA2Payload { path, size };
    let response = BTPResponse::ok(payload);
    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}
