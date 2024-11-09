use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use anyhow::Context;
use rustp2p::config::LocalInterface;
use rustp2p::pipe::PeerNodeAddress;
use serde::de::Visitor;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::cipher::Cipher;

const DEFAULT_ALGORITHM: &str = "chacha20-poly1305";
const UDP_STUN: [&str; 6] = [
    "stun.miwifi.com",
    "stun.chat.bilibili.com",
    "stun.hitv.com",
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];
const TCP_STUN: [&str; 3] = [
    "stun.flashdance.cx",
    "stun.sipnet.net",
    "stun.nextcloud.com:443",
];

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub(crate) listen_route: bool,
    pub(crate) config_name: Option<String>,
    pub(crate) node_ipv4: Ipv4Addr,
    pub(crate) node_ipv6: Ipv6Addr,
    pub(crate) prefix: u8,
    pub(crate) prefix_v6: u8,
    pub(crate) tun_name: Option<String>,
    #[serde(skip_deserializing)]
    #[serde(skip_serializing)]
    pub(crate) cipher: Option<Cipher>,
    pub(crate) encrypt: Option<String>,
    pub(crate) algorithm: Option<String>,
    pub(crate) port: u16,
    pub(crate) group_code: GroupCode,
    pub(crate) peer: Option<Vec<PeerAddress>>,
    pub(crate) bind_dev_name: Option<String>,
    #[serde(skip_deserializing)]
    #[serde(skip_serializing)]
    pub(crate) iface_option: Option<LocalInterface>,
    pub(crate) exit_node: Option<Ipv4Addr>,

    pub(crate) udp_stun: Vec<String>,
    pub(crate) tcp_stun: Vec<String>,
}

#[derive(Default)]
pub struct ConfigBuilder {
    listen_route: Option<bool>,
    config_name: Option<String>,
    node_ipv4: Option<Ipv4Addr>,
    node_ipv6: Option<Ipv6Addr>,
    prefix: Option<u8>,
    prefix_v6: Option<u8>,
    tun_name: Option<String>,
    encrypt: Option<String>,
    algorithm: Option<String>,
    port: Option<u16>,
    group_code: Option<GroupCode>,
    peer: Option<Vec<PeerAddress>>,
    bind_dev_name: Option<String>,
    exit_node: Option<Ipv4Addr>,
    udp_stun: Option<Vec<String>>,
    tcp_stun: Option<Vec<String>>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn listen_route(mut self, listen_route: bool) -> Self {
        self.listen_route = Some(listen_route);
        self
    }
    pub fn config_name(mut self, config_name: String) -> Self {
        self.config_name = Some(config_name);
        self
    }
    pub fn node_ipv4(mut self, node_ipv4: Ipv4Addr) -> Self {
        self.node_ipv4 = Some(node_ipv4);
        self
    }

    pub fn node_ipv6(mut self, node_ipv6: Ipv6Addr) -> Self {
        self.node_ipv6 = Some(node_ipv6);
        self
    }

    pub fn prefix(mut self, prefix: u8) -> Self {
        self.prefix = Some(prefix);
        self
    }

    pub fn prefix_v6(mut self, prefix_v6: u8) -> Self {
        self.prefix_v6 = Some(prefix_v6);
        self
    }

    pub fn tun_name(mut self, tun_name: Option<String>) -> Self {
        self.tun_name = tun_name;
        self
    }

    pub fn encrypt(mut self, encrypt: Option<String>) -> Self {
        self.encrypt = encrypt;
        self
    }

    pub fn algorithm(mut self, algorithm: Option<String>) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn group_code(mut self, group_code: GroupCode) -> Self {
        self.group_code = Some(group_code);
        self
    }

    pub fn peer(mut self, peer: Option<Vec<PeerAddress>>) -> Self {
        self.peer = peer;
        self
    }

    pub fn bind_dev_name(mut self, bind_dev_name: Option<String>) -> Self {
        self.bind_dev_name = bind_dev_name;
        self
    }

    pub fn exit_node(mut self, exit_node: Option<Ipv4Addr>) -> Self {
        self.exit_node = exit_node;
        self
    }

    pub fn udp_stun(mut self, udp_stun: Vec<String>) -> Self {
        self.udp_stun = Some(udp_stun);
        self
    }

    pub fn tcp_stun(mut self, tcp_stun: Vec<String>) -> Self {
        self.tcp_stun = Some(tcp_stun);
        self
    }

    pub fn build(self) -> anyhow::Result<Config> {
        let prefix_v6 = self.prefix_v6.unwrap_or(96);
        let node_ipv4 = self.node_ipv4.context("node_ipv4 is required")?;
        let node_ipv6 = if let Some(node_ipv6) = self.node_ipv6 {
            let mut octets = node_ipv6.octets();
            octets[12..].copy_from_slice(&node_ipv4.octets());

            let node_ipv6 = Ipv6Addr::from(octets);
            if prefix_v6 > 96 {
                Err(anyhow::anyhow!("prefix_v6 cannot be greater than 96"))?
            }
            node_ipv6
        } else {
            let mut v6: [u8; 16] = [
                0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0, 0, 0, 0,
            ];
            v6[12..].copy_from_slice(&node_ipv4.octets());
            Ipv6Addr::from(v6)
        };

        let encrypt = self.encrypt.clone();
        let algorithm = self
            .algorithm
            .clone()
            .unwrap_or(DEFAULT_ALGORITHM.to_string());
        let cipher = match algorithm.to_lowercase().as_str() {
            "aes-gcm" => encrypt.map(Cipher::new_aes_gcm),
            "chacha20-poly1305" => encrypt.map(Cipher::new_chacha20_poly1305),
            "xor" => encrypt.map(Cipher::new_xor),
            t => Err(anyhow::anyhow!("algorithm error: {t}"))?,
        };
        let mut iface_option = None;
        if let Some(bind_dev_name) = self.bind_dev_name.clone() {
            let _bind_dev_index = match crate::platform::dev_name_to_index(&bind_dev_name) {
                Ok(index) => index,
                Err(e) => Err(anyhow::anyhow!("bind_dev_name error: {e}"))?,
            };
            let iface;
            #[cfg(not(target_os = "linux"))]
            {
                iface = LocalInterface::new(_bind_dev_index);
            }
            #[cfg(target_os = "linux")]
            {
                iface = LocalInterface::new(bind_dev_name.clone());
            }
            iface_option.replace(iface);
        }

        let config = Config {
            listen_route: self.listen_route.unwrap_or(true),
            config_name: self.config_name,
            node_ipv4,
            node_ipv6,
            prefix: self.prefix.context("prefix is required")?,
            prefix_v6,
            tun_name: self.tun_name,
            encrypt: self.encrypt,
            algorithm: self.algorithm,
            cipher,
            port: self.port.context("port is required")?,
            group_code: self.group_code.context("group_code is required")?,
            peer: self.peer,
            bind_dev_name: self.bind_dev_name,
            iface_option,
            exit_node: self.exit_node,
            udp_stun: self
                .udp_stun
                .unwrap_or(UDP_STUN.iter().map(|v| v.to_string()).collect()),
            tcp_stun: self
                .tcp_stun
                .unwrap_or(TCP_STUN.iter().map(|v| v.to_string()).collect()),
        };
        Ok(config)
    }
}

#[derive(Debug, Clone)]
pub struct GroupCode(pub rustp2p::protocol::node_id::GroupCode);

impl Display for GroupCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::fmt::Display::fmt(&group_code_to_string(&self.0), f)
    }
}

impl TryFrom<String> for GroupCode {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        GroupCode::from_str(&value)
    }
}

impl FromStr for GroupCode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(GroupCode(string_to_group_code(s)?))
    }
}

impl Serialize for GroupCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for GroupCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GroupCodeVisitor;

        impl<'de> Visitor<'de> for GroupCodeVisitor {
            type Value = GroupCode;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a valid GroupCode string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                GroupCode::from_str(value).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(GroupCodeVisitor)
    }
}

#[derive(Debug, Clone)]
pub struct PeerAddress(pub PeerNodeAddress);

impl Display for PeerAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for PeerAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PeerAddress(PeerNodeAddress::from_str(s)?))
    }
}

impl Serialize for PeerAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PeerAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PeerNodeAddressVisitor;

        impl<'de> Visitor<'de> for PeerNodeAddressVisitor {
            type Value = PeerAddress;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a valid PeerNodeAddress string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                PeerAddress::from_str(value).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(PeerNodeAddressVisitor)
    }
}

pub(crate) fn string_to_group_code(
    input: &str,
) -> anyhow::Result<rustp2p::protocol::node_id::GroupCode> {
    let mut array = [0u8; 16];
    let bytes = input.as_bytes();
    if bytes.len() > 16 {
        return Err(anyhow::anyhow!("group_code is too long"));
    }
    let len = bytes.len();
    array[..len].copy_from_slice(&bytes[..len]);
    Ok(array.into())
}

pub(crate) fn group_code_to_string(group_code: &rustp2p::protocol::node_id::GroupCode) -> String {
    let mut vec = group_code.as_ref().to_vec();
    if let Some(pos) = vec.iter().rposition(|&x| x != 0) {
        vec.truncate(pos + 1);
    }
    match String::from_utf8(vec) {
        Ok(group_code) => group_code,
        Err(_) => format!("{:?}", group_code.as_ref()),
    }
}