use bon::Builder;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct ContainerIdentifiers {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct Addr {
    pub addr: Vec<u8>,
    pub container_id: String,
}

impl Addr {
    pub fn from_ip(ip: IpAddr, container_id: String) -> Self {
        let addr = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        Self { addr, container_id }
    }

    pub fn to_ip(&self) -> Option<IpAddr> {
        match self.addr.len() {
            4 => {
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&self.addr);
                Some(IpAddr::V4(octets.into()))
            }
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&self.addr);
                Some(IpAddr::V6(octets.into()))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct ContainerAlias {
    pub container_id: String,
    pub container_alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct EstContainer {
    pub src_container_id: String,
    pub dst_container_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Builder)]
pub struct WaitingContainerRule {
    pub src_container_id: String,
    pub dst_container_name: String,
}
