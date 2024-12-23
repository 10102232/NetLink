use crate::config::FileConfigView;
use crate::service::ApiService;
use clap::Parser;
use env_logger::Env;
use netlink_http::{Config, ConfigBuilder, HttpUserInfo, PeerAddress};
use std::future::Future;
use std::net::Ipv4Addr;
#[cfg(feature = "web")]
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::net::ToSocketAddrs;
use tokio::net::TcpStream;

mod config;
#[cfg(feature = "web")]
mod interceptor;
mod service;
#[cfg(feature = "web")]
mod static_file;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Peer node address.
    /// e.g.: -p tcp://192.168.10.13:23333 -p udp://192.168.10.23:23333
    #[arg(short, long)]
    peer: Vec<PeerAddress>,
    /// Local node IP and prefix.If there is no 'prefix', Will not enable Tun.
    /// e.g.: -l 10.26.0.2/24
    #[arg(short, long, value_name = "LOCAL IP")]
    local: String,
    /// Nodes with the same group_code can form a network (Maximum length 16).
    #[arg(short, long, value_name = "GROUP CODE")]
    group_code: String,
    /// Listen local port
    #[arg(short = 'P', long, default_value = LISTEN_PORT_STR)]
    port: u16,
    /// Bind the outgoing network interface (using the interface name).
    /// e.g.: -b eth0
    #[arg(short, long, value_name = "DEVICE NAME")]
    bind_dev: Option<String>,
    /// Set the number of threads
    #[arg(long, default_value = "2")]
    threads: usize,
    /// Enable data encryption.
    /// e.g.: -e "password"
    #[arg(short, long, value_name = "PASSWORD")]
    encrypt: Option<String>,
    /// Set encryption algorithm. Optional aes-gcm/chacha20-poly1305/xor
    #[arg(short, long, default_value = DEFAULT_ALGORITHM)]
    algorithm: String,
    /// Global exit node,please use it together with '--bind-dev'
    #[arg(long)]
    exit_node: Option<Ipv4Addr>,
    /// Set tun name
    #[arg(long)]
    tun_name: Option<String>,
    /// Set tun mtu
    #[arg(long)]
    mtu: Option<u16>,
    /// Group code whitelist, using regular expressions
    #[arg(short = 'X', long = "filter")]
    filter: Option<Vec<String>>,
    /// Start using configuration file
    #[arg(short = 'f', long)]
    config: Option<String>,
    /// Set backend http server address
    #[cfg(feature = "web")]
    #[arg(long, default_value = CMD_ADDRESS_STR)]
    api_addr: Option<String>,
    /// Disable backend http server
    #[cfg(feature = "web")]
    #[arg(long)]
    api_disable: bool,

    /// http username to login
    #[cfg(feature = "web")]
    #[arg(long)]
    username: Option<String>,

    /// http password to login
    #[cfg(feature = "web")]
    #[arg(long)]
    password: Option<String>,

    /// Enable logging
    #[arg(long)]
    log_enabled: bool,
}

#[derive(Parser, Debug)]
struct ArgsConfig {
    #[arg(short = 'f', long)]
    config: String,
}

#[derive(Parser, Debug)]
struct ArgsApiConfig {
    #[cfg(feature = "web")]
    #[arg(long, default_value = CMD_ADDRESS_STR)]
    api_addr: String,

    /// http username to login
    #[cfg(feature = "web")]
    #[arg(short, long)]
    username: String,

    /// http password to login
    #[cfg(feature = "web")]
    #[arg(short, long)]
    password: String,

    #[arg(long, default_value = "2")]
    threads: usize,
}
#[cfg(feature = "web")]
const CMD_ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 23336);
#[cfg(feature = "web")]
const CMD_ADDRESS_STR: &str = "127.0.0.1:23336";

const LISTEN_PORT: u16 = 23333;
const LISTEN_PORT_STR: &str = "23333";
const DEFAULT_ALGORITHM: &str = "chacha20-poly1305";

fn block_on<F: Future>(worker_threads: usize, f: F) -> F::Output {
    if worker_threads <= 1 {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }
}

async fn main_by_cmd(args: Option<Args>) -> anyhow::Result<()> {
    if let Some(args) = args {
        let Args {
            peer,
            local,
            group_code,
            port,
            bind_dev,
            encrypt,
            algorithm,
            exit_node,
            tun_name,
            #[cfg(feature = "web")]
            api_addr,
            #[cfg(feature = "web")]
            api_disable,
            #[cfg(feature = "web")]
            username,
            #[cfg(feature = "web")]
            password,
            mtu,
            filter,
            log_enabled,
            ..
        } = args;
        let mut split = local.split('/');
        let self_id =
            Ipv4Addr::from_str(split.next().expect("--local error")).expect("--local error");
        let prefix = if let Some(mask) = split.next() {
            u8::from_str(mask).expect("unable to parse the prefix in the arguments for --local")
        } else {
            0
        };
        let group_code_filter_regex = config::convert_group_filter(filter)?;
        if let Some(v) = group_code_filter_regex.as_ref() {
            log::info!("group code filter regex:{v:?}");
        }
        let config = ConfigBuilder::new()
            .group_code(group_code.try_into()?)
            .config_name(Some("cmd".to_string()))
            .node_ipv4(self_id)
            .prefix(prefix)
            .tun_name(tun_name)
            .encrypt(encrypt)
            .algorithm(Some(algorithm))
            .port(port)
            .peer(Some(peer))
            .bind_dev_name(bind_dev)
            .exit_node(exit_node)
            .mtu(mtu)
            .group_code_filter_regex(group_code_filter_regex)
            .build()?;
        #[cfg(feature = "web")]
        let api_addr = if api_disable {
            None
        } else if let Some(api_addr) = api_addr {
            let addr = SocketAddr::from_str(&api_addr)
                .map_err(|e| anyhow::anyhow!("cmd --addr {api_addr:?}, {e}"))?;
            Some(addr)
        } else {
            Some(CMD_ADDRESS)
        };
        start_by_config(
            Some(config),
            #[cfg(feature = "web")]
            api_addr,
            #[cfg(feature = "web")]
            username,
            #[cfg(feature = "web")]
            password,
        )
        .await?;
    } else {
        start_by_config(
            None,
            #[cfg(feature = "web")]
            Some(SocketAddr::from_str(CMD_ADDRESS_STR).unwrap()),
            #[cfg(feature = "web")]
            None,
            #[cfg(feature = "web")]
            None,
        )
        .await?;
    }

    Ok(())
}

fn resolve_domain(domain: &str) -> Option<SocketAddr> {
    let addrs: Vec<SocketAddr> = (domain, 0).to_socket_addrs().ok()?.collect();
    addrs.into_iter().find(|addr| matches!(addr, SocketAddr::V4(_)))
}

async fn main_by_config_file(file_config: FileConfigView) -> anyhow::Result<()> {
    #[cfg(feature = "web")]
    let addr = if file_config.api_disable {
        None
    } else {
        Some(file_config.api_addr)
    };
    let username = file_config.username.clone();
    let password = file_config.password.clone();
    let config = file_config.try_into()?;
    start_by_config(
        Some(config),
        #[cfg(feature = "web")]
        addr,
        #[cfg(feature = "web")]
        username,
        #[cfg(feature = "web")]
        password,
    )
    .await
}

async fn start_by_config(
    config: Option<Config>,
    #[cfg(feature = "web")] cmd_server_addr: Option<SocketAddr>,
    #[cfg(feature = "web")] username: Option<String>,
    #[cfg(feature = "web")] password: Option<String>,
) -> anyhow::Result<()> {
    let api_service = ApiService::new(config).await?;
    #[cfg(feature = "web")]
    if let Some(cmd_server_addr) = cmd_server_addr {
        let handle = interceptor::ApiInterceptor::new(api_service.clone());
        let user_info = match (username, password) {
            (Some(username), Some(password)) => Some(HttpUserInfo { username, password }),
            (None, None) => None,
            _ => {
                log::warn!("Missing user or password,login configuration does not take effect");
                None
            }
        };
        let http_config = netlink_http::HttpConfiguration {
            addr: cmd_server_addr,
            user_info,
        };
        if let Err(e) = netlink_http::web_server::start(
            http_config,
            api_service.inner_api(),
            Some(handle),
            static_file::StaticAssets,
        )
        .await
        {
            return Err(anyhow::anyhow!("The backend command port has already been used. Please use 'cmd --api-addr' to change the port, err={e}"));
        }
    }

    let (tx, mut quit) = tokio::sync::mpsc::channel::<()>(1);

    ctrlc2::set_async_handler(async move {
        let _ = tx.send(()).await;
    })
    .await;
    if api_service.exist_config() {
        api_service.open().await?;
    } else {
        #[cfg(not(feature = "web"))]
        Err(anyhow::anyhow!("Configuration not found"))?
    }
    _ = quit.recv().await;
    _ = api_service.close();
    log::info!("exit!!!!");
    Ok(())
}

async fn connect_to_domain(domain: &str) -> anyhow::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = (domain, 0).to_socket_addrs()?
        .collect();
    
    if let Some(ipv6_addr) = addrs.iter().find(|addr| matches!(addr, SocketAddr::V6(_))) {
        if let Ok(stream) = TcpStream::connect(ipv6_addr).await {
            println!("Connected to IPv6 address: {}", ipv6_addr);
            return Ok(stream);
        } else {
            println!("Failed to connect to IPv6 address: {}", ipv6_addr);
        }
    }

    if let Some(ipv4_addr) = addrs.iter().find(|addr| matches!(addr, SocketAddr::V4(_))) {
        if let Ok(stream) = TcpStream::connect(ipv4_addr).await {
            println!("Connected to IPv4 address: {}", ipv4_addr);
            return Ok(stream);
        } else {
            println!("Failed to connect to IPv4 address: {}", ipv4_addr);
        }
    }

    Err(anyhow::anyhow!("Failed to connect to any address for domain: {}", domain))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = match Args::try_parse() {
        Ok(arg) => arg,
        Err(e) => {
            if let Ok(args) = ArgsConfig::try_parse() {
                let file_config = FileConfigView::read_file(&args.config)?;
                let worker_threads = file_config.threads;
                return block_on(worker_threads, main_by_config_file(file_config));
            }

            if let Ok(args) = ArgsApiConfig::try_parse() {
                return block_on(
                    args.threads,
                    start_by_config(
                        None,
                        #[cfg(feature = "web")]
                        Some(SocketAddr::from_str(&args.api_addr)?),
                        #[cfg(feature = "web")]
                        Some(args.username),
                        #[cfg(feature = "web")]
                        Some(args.password),
                    ),
                );
            }
            println!("{e}");
            return Ok(());
        }
    };

    if args.log_enabled {
        env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    }

    let worker_threads = args.threads;
    block_on(worker_threads, main_by_cmd(Some(args)))
}
