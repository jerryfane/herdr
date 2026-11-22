use super::guest::{parse, send};
use crate::api::schema::{
    Method, OwnerAccessAddParams, OwnerAccessInfoParams, OwnerAccessListParams,
    OwnerAccessRemoveParams, OwnerAccessRenewParams, OwnerScope,
};

const HELP: &str = "Usage:
  herdr owner-access info
  herdr owner-access list
  herdr owner-access add --device-pub KEY --device-name NAME --scope chat|terminal --ttl SECS --statement JWS --approved-by NAME
  herdr owner-access renew <grant-id> --ttl SECS [--scope chat|terminal]
  herdr owner-access remove <grant-id> | --device-pub KEY | --fingerprint FINGERPRINT

Allow your own browsers on this machine through the HerdrUp guest relay.
Each grant names one browser key, is bound to the HerdrUp account of the
device that approved it (--statement is that device's account statement for
this machine), and lasts 1 hour to 30 days (--ttl 3600 to 2592000). Terminal
access is a shell on this machine. While a grant is live the relay link is up.
info prints this machine's relay id and public key. HerdrUp runs these for you
when you approve a browser.";

pub(super) fn run_owner_access_command(args: &[String]) -> std::io::Result<i32> {
    let result = match args.first().map(String::as_str) {
        Some("info") => info(&args[1..]),
        Some("list") => list(&args[1..]),
        Some("add") => add(&args[1..]),
        Some("renew") => renew(&args[1..]),
        Some("remove") => remove(&args[1..]),
        Some("help" | "--help" | "-h") => {
            println!("{HELP}");
            return Ok(0);
        }
        _ => Err(String::new()),
    };
    match result {
        Ok(code) => Ok(code),
        Err(message) => {
            if !message.is_empty() {
                eprintln!("{message}");
            }
            eprintln!("{HELP}");
            Ok(2)
        }
    }
}

fn scope(value: &str) -> Result<OwnerScope, String> {
    match value {
        "chat" => Ok(OwnerScope::Chat),
        "terminal" => Ok(OwnerScope::Terminal),
        _ => Err("--scope takes chat or terminal".into()),
    }
}

fn ttl(value: Option<String>) -> Result<u64, String> {
    value
        .ok_or("--ttl is required")?
        .parse::<u64>()
        .map_err(|_| "--ttl must be seconds".into())
}

fn info(args: &[String]) -> Result<i32, String> {
    if !parse(args, &[])?.positional.is_empty() {
        return Err("info takes no arguments".into());
    }
    send(
        "cli:owner-access:info",
        Method::OwnerAccessInfo(OwnerAccessInfoParams {}),
    )
    .map_err(|err| err.to_string())
}

fn list(args: &[String]) -> Result<i32, String> {
    if !parse(args, &[])?.positional.is_empty() {
        return Err("list takes no arguments".into());
    }
    send(
        "cli:owner-access:list",
        Method::OwnerAccessList(OwnerAccessListParams {}),
    )
    .map_err(|err| err.to_string())
}

fn add(args: &[String]) -> Result<i32, String> {
    let parsed = parse(
        args,
        &[
            "device-pub",
            "device-name",
            "scope",
            "ttl",
            "statement",
            "approved-by",
        ],
    )?;
    if !parsed.positional.is_empty() {
        return Err("add takes only options".into());
    }
    let required = |name: &str| {
        parsed
            .option(name)
            .ok_or_else(|| format!("--{name} is required"))
    };
    let params = OwnerAccessAddParams {
        device_pub: required("device-pub")?,
        device_name: required("device-name")?,
        scope: scope(&required("scope")?)?,
        ttl_secs: ttl(parsed.option("ttl"))?,
        account_statement: required("statement")?,
        approved_by: required("approved-by")?,
    };
    send("cli:owner-access:add", Method::OwnerAccessAdd(params)).map_err(|err| err.to_string())
}

fn renew(args: &[String]) -> Result<i32, String> {
    let parsed = parse(args, &["ttl", "scope"])?;
    let [grant_id] = parsed.positional.as_slice() else {
        return Err("renew takes exactly one grant id".into());
    };
    let params = OwnerAccessRenewParams {
        grant_id: grant_id.clone(),
        ttl_secs: ttl(parsed.option("ttl"))?,
        scope: parsed.option("scope").as_deref().map(scope).transpose()?,
    };
    send("cli:owner-access:renew", Method::OwnerAccessRenew(params)).map_err(|err| err.to_string())
}

fn remove(args: &[String]) -> Result<i32, String> {
    let parsed = parse(args, &["device-pub", "fingerprint"])?;
    let params = match (
        parsed.positional.as_slice(),
        parsed.option("device-pub"),
        parsed.option("fingerprint"),
    ) {
        ([grant_id], None, None) => OwnerAccessRemoveParams {
            grant_id: Some(grant_id.clone()),
            ..Default::default()
        },
        ([], Some(device_pub), None) => OwnerAccessRemoveParams {
            device_pub: Some(device_pub),
            ..Default::default()
        },
        ([], None, Some(fingerprint)) => OwnerAccessRemoveParams {
            fingerprint: Some(fingerprint),
            ..Default::default()
        },
        _ => return Err("remove takes one grant id, --device-pub or --fingerprint".into()),
    };
    send("cli:owner-access:remove", Method::OwnerAccessRemove(params))
        .map_err(|err| err.to_string())
}
