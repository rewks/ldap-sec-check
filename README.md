# ldap-sec-check

Rust tool to perform a variety of binds to LDAP servers, determining their policies regarding LDAP signing and channel binding.

The use case is to find domain controllers in an Active Directory domain that can be used in a relay to LDAP attack.

Credit to https://github.com/zyn3rgy/LdapRelayScan for the concept and work on how to identify the different channel binding policy levels.

## Usage

**Note**: If you provide incorrect credentials the tool will abort all remaining tests after the first authentication failure. This is to avoid unnecessary lockouts.

```
Usage: ldap-sec-check [OPTIONS] --username <USERNAME> --password <PASSWORD> --target <TARGET>

Options:
  -u, --username <USERNAME>  
  -p, --password <PASSWORD>  
  -t, --target <TARGET>      IP address or fully qualified name of target domain controller
  -a, --all                  Lookup and test all domain controllers
  -d, --domain <FQDN>        Fully qualified domain name (required only if anonymous bind fails)
  -h, --help                 Print help
  -V, --version              Print version
```

- Username, password and target are mandatory.
- `-a / --all`: Optional. If specified then DNS lookups will be performed against the given target to identify all the other domain controllers in the domain and all of them will be checked for signing/channel binding.
- `-d / --domain`: Optional. The fully-qualified domain name of the domain. If not provided, an anonymous bind will be performed against the target to retrieve it.

**Example Output**:

```
rewks@devbox:~$ ./ldap-sec-check -t 192.168.120.132 -u ted -p password -a
Domain: corp.local
User: ted@corp.local

dc01.corp.local: Signing = Required | Channel Binding = When supported
dc02.corp.local: Signing = Required | Channel Binding = When supported
```

## Installation

Either grab a pre-build binary for your system from the releases page or clone the repository and build with cargo:

```
git clone https://github.com/rewks/LdapSecCheck.git
cd LdapSecCheck
cargo build --release
```