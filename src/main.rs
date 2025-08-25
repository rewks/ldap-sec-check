use clap::Parser;
use ldap3::{result::Result, LdapConn, Scope, SearchEntry};
use colored::*;

use std::net::ToSocketAddrs;

use std::net::*;
use tokio::runtime::Runtime;
use hickory_resolver::Resolver;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::config::*;

#[derive(Parser, Debug)]
#[command(name = "LdapSecCheck")]
#[command(version = "0.1.0")]
#[command(about = "Checks if domain controllers require LDAP signing or channel binding", long_about = None)]
struct Args {
    #[arg(short, long)]
    username: String,

    #[arg(short, long)]
    password: String,

    #[arg(short, long)]
    target: String,

    #[arg(short, long, help = "Find and test all domain controllers")]
    all: bool,
    
    #[arg(short, long, value_name = "FQDN")]
    domain: Option<String>,
}

fn get_domain_through_anonymous_bind(ldap_server: &String) -> Result<Option<String>> {
    println!("Performing anonymous bind to {} to enumerate domain's distinguished name", ldap_server);
    let ldap_address = format!("ldap://{}", ldap_server);

    let mut ldap = LdapConn::new(&ldap_address)?;
    ldap.simple_bind("", "")?.success()?;

    let (results, _res) = ldap.search(
        "",
        Scope::Base,
        "(objectClass=*)",
        vec!["defaultNamingContext"]
    )?.success()?;
    
    if let Some(entry) = results.get(0) {
        let se = SearchEntry::construct(entry.clone());
        if let Some(default_naming_context) = se.attrs.get("defaultNamingContext") {
            if let Some(first) = default_naming_context.get(0) {
                return Ok(Some(first.clone()));
            }
        }
    }

    ldap.unbind()?;

    Ok(None)
}

fn dn_to_fqdn(distinguished_name: &str) -> String {
    distinguished_name.split(',')
        .filter_map(|relative_distinguished_name| {
            let mut rdn_parts = relative_distinguished_name.splitn(2, '=');
            match (rdn_parts.next(), rdn_parts.next()) {
                (Some(attrribute), Some(value)) if attrribute.eq_ignore_ascii_case("DC") => Some(value),
                _ => None,
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn lookup_domain_controllers(nameserver: &str, domain: &str) -> Vec<String> {
    // Tokio Runtime to run the resolver
    let io_loop = Runtime::new().unwrap();

    let nameserver_ip = nameserver.parse::<IpAddr>().unwrap();
    let nameserver_config = NameServerConfig::new(
        std::net::SocketAddr::new(nameserver_ip, 53),
        hickory_proto::xfer::Protocol::Udp
    );

    let resolver_config = ResolverConfig::from_parts(
        None,
        vec![],
        vec![nameserver_config]
    );

    let resolver = Resolver::builder_with_config(
        resolver_config,
        TokioConnectionProvider::default()
    ).build();

    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7fcdce70-5205-44d6-9c3a-260e616a2f04
    let srv_record = format!("_ldap._tcp.dc._msdcs.{}", domain);

    let lookup_future = resolver.srv_lookup(&srv_record);

    // Run the lookup until it resolves or errors
    let response = io_loop.block_on(lookup_future).unwrap(); // need to handle errors from incorrect domains better

    let mut domain_controllers: Vec<String> = response
        .iter()
        .map(|r| r.target().to_utf8().trim_end_matches('.').to_string())
        .collect();

    domain_controllers.sort_by_key(|s| s.to_lowercase());
    domain_controllers
    
}

fn check_signing_requirement(target: &str, user_string: &str, password: &str) -> Result<ldap3::LdapResult> {
    let ldap_address = format!("ldap://{}", target);

    let mut ldap = LdapConn::new(&ldap_address)?;
    let bind_result = ldap.simple_bind(&user_string, &password)?;
    ldap.unbind()?;

    Ok(bind_result)
}

fn resolve_to_ip(address: &str) -> Result<IpAddr> {
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Ok(ip);
    }

    let addr = format!("{}:0", address)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Could not resolve {}", address)
        ))?;

    Ok(addr.ip())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Use IP address if given, otherwise try to resolve target name to an IP address
    // required for DNS lookups where nameserver must be given in IPv4 or IPv6 form
    let target_ip = resolve_to_ip(&args.target)?.to_string();

    // Use user-supplied FQDN if given, otherwise try to enumerate it through anonymous bind
    let fqdn = if let Some(d) = args.domain {
        d
    } else {
        match get_domain_through_anonymous_bind(&args.target)? {
            Some(dn) => dn_to_fqdn(&dn),
            None =>  {
                eprintln!("Domain name not found through anonymous bind. Try specifying the domain with -d <domain>");
                std::process::exit(1);
            }
        }
    };

    let user_string = format!("{}@{}", args.username, fqdn);
    
    let domain_controllers = match args.all {
        true => lookup_domain_controllers(&target_ip, &fqdn),
        false => vec![String::from(args.target)]
    };

    let mut failed_auth = false;
    for dc in domain_controllers.iter() {
        // LDAP result codes: https://datatracker.ietf.org/doc/html/rfc4511#appendix-A.1

        let signing_status = if failed_auth {
            "Aborted".to_string()
        } else {
            let ldap_result = check_signing_requirement(&dc, &user_string, &args.password)?;
            match ldap_result.rc {          
                0 => "Signing NOT required".red().to_string(),
                8 => "Signing required".green().to_string(),
                49 => {
                    failed_auth = true;
                    "Invalid credentials, aborting tests".yellow().bold().to_string()
                },
                _ => ldap_result.text
            }
        };

        let channel_binding_status = if failed_auth {
            "Aborted".to_string()
        } else {
            "Not implemented".to_string()
        };

        println!("{}: Signing = {} | Channel Binding = {}", dc.bold(), signing_status, channel_binding_status);
    }

    Ok(())
}
