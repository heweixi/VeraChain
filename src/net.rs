//! 网络辅助:可信代理列表(CIDR/单 IP)解析与匹配。
//!
//! 本模块只提供 `trusted_proxies` 配置的解析与成员判断;`X-Forwarded-For` 取址
//! (`resolve_client_ip`)由后续切片接入。手写 CIDR,不引入额外依赖。
use std::net::IpAddr;

/// `X-Forwarded-For` 最多处理的条目数(供 XFF 解析切片使用,超出视为不可信输入)。
pub const MAX_XFF_ENTRIES: usize = 32;
/// `X-Forwarded-For` 头总字节数上限(供 XFF 解析切片使用)。
pub const MAX_XFF_BYTES: usize = 2048;

/// 一条已规整的网络前缀(地址已按掩码清零主机位)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cidr {
    V4 { net: u32, mask: u32 },
    V6 { net: u128, mask: u128 },
}

impl Cidr {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { net, mask }, IpAddr::V4(v4)) => u32::from(v4) & mask == *net,
            (Cidr::V6 { net, mask }, IpAddr::V6(v6)) => u128::from(v6) & mask == *net,
            _ => false,
        }
    }
}

/// 可信代理集合。空集合表示不信任任何代理(默认,与未配置时行为一致)。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    nets: Vec<Cidr>,
}

impl TrustedProxies {
    /// 解析配置项。每项为单个 IP 或 `地址/前缀`;拒绝空项、非法地址、
    /// 越界前缀(IPv4 > 32、IPv6 > 128)与 `/0`(会信任全部来源)。
    /// 非对齐写法按掩码规整(`10.1.2.3/8` 等价于 `10.0.0.0/8`),重复项不报错。
    pub fn parse(items: &[String]) -> Result<Self, String> {
        let mut nets = Vec::with_capacity(items.len());
        for (index, raw) in items.iter().enumerate() {
            let cidr = Self::parse_one(raw.trim())
                .map_err(|reason| format!("entry #{} is invalid: {}", index + 1, reason))?;
            if !nets.contains(&cidr) {
                nets.push(cidr);
            }
        }
        Ok(Self { nets })
    }

    fn parse_one(text: &str) -> Result<Cidr, &'static str> {
        if text.is_empty() {
            return Err("empty entry");
        }
        let (addr_text, prefix_text) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr_text.parse().map_err(|_| "not a valid IP address")?;
        let max_prefix: u32 = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            None => max_prefix,
            Some(p) => {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("prefix length must be a decimal number");
                }
                let value: u32 = p.parse().map_err(|_| "prefix length out of range")?;
                if value > max_prefix {
                    return Err("prefix length out of range");
                }
                if value == 0 {
                    return Err("prefix length /0 is not allowed");
                }
                value
            }
        };
        Ok(match addr {
            IpAddr::V4(v4) => {
                let mask = u32::MAX << (32 - prefix);
                Cidr::V4 {
                    net: u32::from(v4) & mask,
                    mask,
                }
            }
            IpAddr::V6(v6) => {
                let mask = u128::MAX << (128 - prefix);
                Cidr::V6 {
                    net: u128::from(v6) & mask,
                    mask,
                }
            }
        })
    }

    /// 是否没有任何可信代理。
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// `ip` 是否落在任一可信网段内。IPv4 映射的 IPv6 地址(`::ffff:a.b.c.d`)按 IPv4 判断。
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        self.nets.iter().any(|net| net.contains(ip))
    }
}

/// 把 `::ffff:a.b.c.d` 规范化为 IPv4,其余原样返回。
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}
