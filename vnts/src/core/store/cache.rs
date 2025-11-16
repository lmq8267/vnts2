use dashmap::DashMap;
use parking_lot::RwLock;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;  
use std::path::PathBuf;  
use std::fs;  
use serde::{Serialize, Deserialize}; 
use boringtun::x25519::{StaticSecret, PublicKey};

use crate::cipher::Aes256GcmCipher;
use crate::core::entity::{NetworkInfo, WireGuardConfig, ClientInfo};
use crate::core::store::expire_map::ExpireMap;
use ipnetwork::Ipv4Network;

// 获取 vnts_wg 目录  
fn get_wg_dir() -> PathBuf {  
    let program_dir = if let Ok(exe_path) = std::env::current_exe() {  
        if let Some(dir) = exe_path.parent() {  
            dir.to_path_buf()  
        } else {  
            PathBuf::from(".")  
        }  
    } else {  
        PathBuf::from(".")  
    };  
      
    let wg_dir = program_dir.join("vnts_wg");  
      
    // 确保目录存在  
    if !wg_dir.exists() {  
        if let Err(e) = fs::create_dir_all(&wg_dir) {  
            log::warn!("创建 vnts_wg 目录失败: {:?}", e);  
        }  
    }  
      
    wg_dir  
}  

#[derive(Serialize, Deserialize)]  
struct WireGuardConfigStore {  
    configs: Vec<WireGuardConfig>,  
} 

#[derive(Serialize, Deserialize)]  
struct ServerWgKeys {  
    secret_key: Vec<u8>,  
    public_key: Vec<u8>,  
}

#[derive(Clone)]
pub struct AppCache {
    // group -> NetworkInfo
    pub virtual_network: ExpireMap<String, Arc<RwLock<NetworkInfo>>>,
    // (group,ip) -> addr  用于客户端过期，只有客户端离线才设置
    pub ip_session: ExpireMap<(String, u32), SocketAddr>,
    // 加密密钥
    pub cipher_session: Arc<DashMap<SocketAddr, Arc<Aes256GcmCipher>>>,
    // web登录状态
    pub auth_map: ExpireMap<String, ()>,
    // wg公钥 -> wg配置
    pub wg_group_map: Arc<DashMap<[u8; 32], WireGuardConfig>>,
}

pub struct VntContext {
    pub link_context: Option<LinkVntContext>,
    pub server_cipher: Option<Aes256GcmCipher>,
    pub link_address: SocketAddr,
}
pub struct LinkVntContext {
    pub network_info: Arc<RwLock<NetworkInfo>>,
    pub group: String,
    pub virtual_ip: u32,
    pub broadcast: Ipv4Addr,
    pub timestamp: i64,
}
impl VntContext {
    pub async fn leave(self, cache: &AppCache) {
        if self.server_cipher.is_some() {
            cache.cipher_session.remove(&self.link_address);
        }
        if let Some(context) = self.link_context {
            if let Some(network_info) = cache.virtual_network.get(&context.group) {
                {
                    let mut guard = network_info.write();
                    if let Some(client_info) = guard.clients.get_mut(&context.virtual_ip) {
                        if client_info.address != self.link_address
                            && client_info.timestamp != context.timestamp
                        {
                            return;
                        }
                        client_info.online = false;
                        client_info.tcp_sender = None;
                        guard.epoch += 1;
                    }
                    drop(guard);
                }
                cache
                    .insert_ip_session((context.group, context.virtual_ip), self.link_address)
                    .await;
            }
        }
    }
}

impl AppCache {
    pub fn new() -> Self {
        let wg_group_map: Arc<DashMap<[u8; 32], WireGuardConfig>> = Default::default();
        // 网段7天未使用则回收
        let virtual_network: ExpireMap<String, Arc<RwLock<NetworkInfo>>> =
            ExpireMap::new(|_k, v: &Arc<RwLock<NetworkInfo>>| {
                let lock = v.read();
                if !lock.clients.is_empty() {
                    // 存在客户端的不过期
                    return Some(Duration::from_secs(7 * 24 * 3600));
                }
                None
            });
        let virtual_network_ = virtual_network.clone();
        // ip一天未使用则回收
        let ip_session: ExpireMap<(String, u32), SocketAddr> = ExpireMap::new(move |key, addr| {
            let (group_id, ip) = &key;
            log::info!(
                "ip_session eviction group_id={},ip={},addr={}",
                group_id,
                Ipv4Addr::from(*ip),
                addr
            );
            if let Some(v) = virtual_network_.get(group_id) {
                let mut lock = v.write();
                if let Some(dev) = lock.clients.get(ip) {
                    if !dev.online && &dev.address == addr {
                        lock.clients.remove(ip);
                        lock.epoch += 1;
                    }
                }
            }
            None
        });

        let auth_map = ExpireMap::new(|_k, _v| None);
        Self {
            virtual_network,
            ip_session,
            cipher_session: Default::default(),
            auth_map,
            wg_group_map,
        }
    }
    // 加载WireGuard客户端配置  
    pub async fn load_wg_configs(&self, gateway: Ipv4Addr, netmask: Ipv4Addr) -> anyhow::Result<()> {  
        let config_path = get_wg_dir().join("client_configs.json");  
        if !config_path.exists() {  
            log::info!("WireGuard配置文件不存在: {:?}", config_path);  
            return Ok(());  
        }  
        let content = fs::read_to_string(&config_path)?;  
        let store: WireGuardConfigStore = serde_json::from_str(&content)?;  
      
        for config in store.configs {  
            // 使用 get 方法检查是否存在,而不是 contains_key  
            if self.virtual_network.get(&config.group_id).is_none() {  
                let network = Ipv4Network::with_netmask(gateway, netmask)?;  
                let network_info = Arc::new(RwLock::new(NetworkInfo::new(  
                    u32::from(network.network()),  
                    u32::from(netmask),  
                    u32::from(gateway),  
                )));  
                self.virtual_network.insert(  
                    config.group_id.clone(),   
                    network_info,   
                    Duration::from_secs(7 * 24 * 3600)  
                ).await;   
            }  
          
            // 将客户端信息添加到网络中  
            if let Some(network_info) = self.virtual_network.get(&config.group_id) {  
                let mut guard = network_info.write();  
                guard.clients.entry(config.ip.into()).or_insert_with(|| ClientInfo {  
                    virtual_ip: config.ip.into(),  
                    device_id: config.device_id.clone(),  
                    name: config.device_id.clone(),  
                    version: String::from("wg"),  
                    wireguard: Some(config.public_key),  
                    online: false,  
                    address: SocketAddr::from(([0, 0, 0, 0], 0)),  
                    client_secret: true,  
                    client_secret_hash: vec![],  
                    server_secret: true,  
                    tcp_sender: None,  
                    wg_sender: None,  
                    client_status: None,  
                    last_join_time: chrono::Local::now(),  
                    timestamp: chrono::Local::now().timestamp(),  
                });  
            }  
          
            self.wg_group_map.insert(config.public_key, config);  
        }  
      
        log::info!("成功加载 {} 个WireGuard配置从 {:?}", self.wg_group_map.len(), config_path);  
        Ok(())  
    }
      
    // 保存WireGuard客户端配置  
    pub fn save_wg_configs(&self) -> anyhow::Result<()> {  
        let config_path = get_wg_dir().join("client_configs.json");  
        let configs: Vec<WireGuardConfig> = self.wg_group_map  
            .iter()  
            .map(|entry| entry.value().clone())  
            .collect();  
          
        let count = configs.len();  
        let store = WireGuardConfigStore { configs };  
        let content = serde_json::to_string_pretty(&store)?;  
        fs::write(&config_path, content)?;  
        log::info!("成功保存 {} 个WireGuard配置到 {:?}", count, config_path);  
        Ok(())  
    }  
}

// 加载或生成服务器WireGuard密钥对  
pub fn load_or_generate_server_wg_keys() -> (StaticSecret, PublicKey) {  
    let key_path = get_wg_dir().join("server_keys.json");  
      
    // 尝试加载现有密钥  
    if key_path.exists() {  
        if let Ok(content) = fs::read_to_string(&key_path) {  
            if let Ok(keys) = serde_json::from_str::<ServerWgKeys>(&content) {  
                if keys.secret_key.len() == 32 {  
                    let mut secret_bytes = [0u8; 32];  
                    secret_bytes.copy_from_slice(&keys.secret_key);  
                    let secret = StaticSecret::from(secret_bytes);  
                    let public = PublicKey::from(&secret);  
                    log::info!("成功加载服务器WireGuard密钥对从 {:?}", key_path);  
                    return (secret, public);  
                }  
            }  
        }  
        log::warn!("加载服务器WireGuard密钥对失败,将生成新的密钥对");  
    }  
      
    // 生成新密钥对  
    let secret = StaticSecret::random_from_rng(rand::thread_rng());  
    let public = PublicKey::from(&secret);  
      
    // 保存密钥对  
    let keys = ServerWgKeys {  
        secret_key: secret.to_bytes().to_vec(),  
        public_key: public.as_bytes().to_vec(),  
    };  
      
    if let Ok(content) = serde_json::to_string_pretty(&keys) {  
        if let Err(e) = fs::write(&key_path, content) {  
            log::warn!("保存服务器WireGuard密钥对失败: {:?}", e);  
        } else {  
            log::info!("成功生成并保存服务器WireGuard密钥对到 {:?}", key_path);  
        }  
    }  
      
    (secret, public)  
}

impl AppCache {
    pub async fn insert_cipher_session(&self, key: SocketAddr, value: Aes256GcmCipher) {
        self.cipher_session.insert(key, Arc::new(value));
    }
    pub async fn insert_ip_session(&self, key: (String, u32), value: SocketAddr) {
        self.ip_session
            .insert(key, value, Duration::from_secs(24 * 3600))
            .await
    }
}
