use clap::Parser;
use ldap3::{result::Result, LdapConn, Scope, SearchEntry};

#[derive(Parser, Debug)]
#[command(name = "LdapSecCheck")]
#[command(version = "0.1.0")]
#[command(about = "Checks if targets require LDAP signing or Channel Binding", long_about = None)]
struct Args {
    #[arg(short, long)]
    username: String,

    #[arg(short, long)]
    password: String,
    
    #[arg(short, long)]
    domain: Option<String>,

    #[arg(short, long)]
    target: String,
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

fn main() -> Result<()> {
    let args = Args::parse();

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
    
    println!("Domain: {}", fqdn); // debug
    println!("Connecting to {} using {}@{}:{}", args.target, args.username, fqdn, args.password); //debug

    Ok(())
}
