use nftables::{
    helper::{DEFAULT_NFT, get_current_ruleset_with_args},
    schema::{Chain, NfListObject},
    types::NfFamily,
};

use crate::Error;

pub fn find_chain<'a>(table: &str, chain_name: &str) -> Result<Option<Chain<'a>>, Error> {
    Ok(
        get_current_ruleset_with_args(DEFAULT_NFT, vec!["list", "chain", "ip", table, chain_name])
            .map_err(|e| Error::Nftables {
                message: format!("Failed to get chain {}: {}", chain_name, e),
                command: Some("get_current_ruleset_with_args".to_string()),
                exit_code: None,
                stderr: Some(e.to_string()),
            })?
            .objects
            .into_iter()
            .find_map(|nf_object| match nf_object {
                nftables::schema::NfObject::ListObject(NfListObject::Chain(chain))
                    if chain.name == chain_name =>
                {
                    Some(chain.to_owned())
                }
                _ => None,
            }),
    )
}
/// Convert NfFamily to string for nft command
pub fn family_to_string(family: &NfFamily) -> &'static str {
    match family {
        NfFamily::IP => "ip",
        NfFamily::IP6 => "ip6",
        NfFamily::INet => "inet",
        NfFamily::ARP => "arp",
        NfFamily::Bridge => "bridge",
        NfFamily::NetDev => "netdev",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_family_to_string_ip() {
        assert_eq!(family_to_string(&NfFamily::IP), "ip");
    }

    #[test]
    fn test_family_to_string_ip6() {
        assert_eq!(family_to_string(&NfFamily::IP6), "ip6");
    }

    #[test]
    fn test_family_to_string_inet() {
        assert_eq!(family_to_string(&NfFamily::INet), "inet");
    }

    #[test]
    fn test_family_to_string_arp() {
        assert_eq!(family_to_string(&NfFamily::ARP), "arp");
    }

    #[test]
    fn test_family_to_string_bridge() {
        assert_eq!(family_to_string(&NfFamily::Bridge), "bridge");
    }

    #[test]
    fn test_family_to_string_netdev() {
        assert_eq!(family_to_string(&NfFamily::NetDev), "netdev");
    }
}
