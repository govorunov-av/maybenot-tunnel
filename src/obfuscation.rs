use enum_map::EnumMap;
use log::info;
use maybenot::{
    event::Event, state::State, state::Trans, Framework, Machine, MachineId, TriggerAction,
    TriggerEvent,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tokio::time::sleep;

pub type MaybenotFramework = Arc<Mutex<Framework<&'static [Machine], StdRng>>>;

pub const MAX_FRAGMENT_SIZE: usize = 1024;
pub const MIN_FRAGMENT_SIZE: usize = 64;
pub const MAX_PADDING_SIZE: usize = 128;
pub const IDLE_THRESHOLD_MS: u64 = 2000;
pub const DUMMY_TRAFFIC_INTERVAL_MS: u64 = 2000;

pub fn init_maybenot() -> MaybenotFramework {
    let rng = StdRng::from_os_rng();

    let empty_transitions: EnumMap<Event, Vec<Trans>> = Default::default();

    let machine_vec = vec![
        Machine::new(1, 0.5, 5, 0.8, vec![State::new(empty_transitions)])
            .expect("❌ Error while creating machine"),
    ];

    let machine_static: &'static [Machine] = Box::leak(Box::new(machine_vec));

    let framework = Framework::new(machine_static, 0.5, 0.8, Instant::now(), rng)
        .expect("❌ Error while initializing Maybenot!");

    info!("✅ Maybenot Framework initialized.");
    Arc::new(Mutex::new(framework))
}

pub async fn obfuscate_data(framework: &MaybenotFramework, data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    // TLS detection
    if data.len() >= 5 {
        let record_type = data[0];
        let version_major = data[1];
        let version_minor = data[2];

        let is_tls_record =
            record_type == 22 || record_type == 20 || record_type == 21 || record_type == 23;

        let is_tls_version = version_major == 3 && version_minor <= 4;

        if is_tls_record && is_tls_version {
            info!("🔒 Detected TLS traffic, passing through without obfuscation");
            return data.to_vec();
        }

        if data.len() >= 9 && record_type == 22 && data[5] == 1 {
            info!("🔒 Detected TLS Client Hello, passing through without obfuscation");
            return data.to_vec();
        }
    }

    if data.len() >= 4 {
        let non_text_chars = data
            .iter()
            .take(32)
            .filter(|&&b| (b < 32 || b > 126) && b != b'\n' && b != b'\r' && b != b'\t')
            .count();

        if non_text_chars > 8 {
            return data.to_vec();
        }

        let first_bytes = [data[0], data[1]];
        if first_bytes != [0xAA, 0xBB] && first_bytes != [0xCC, 0xDD] && first_bytes != [0xEE, 0xFF]
        {
            if (data[0] == 0x1F && data[1] == 0x8B)
                || (data[0] == 0x50 && data[1] == 0x4B)
                || (data[0] == 0xFF && data[1] == 0xD8)
            {
                return data.to_vec();
            }
        }
    }

    let first_bytes = [data[0], data[1]];
    let is_text = data
        .iter()
        .take(20)
        .all(|&b| b >= 32 && b <= 126 || b == b'\n' || b == b'\r' || b == b'\t');

    if !is_text
        && first_bytes != [0xAA, 0xBB]
        && first_bytes != [0xCC, 0xDD]
        && first_bytes != [0xEE, 0xFF]
    {
        return data.to_vec();
    }

    let mut fw = framework.lock().await;
    let machine_id = MachineId::from_raw(0);

    let mut actions = fw.trigger_events(
        &[TriggerEvent::PaddingSent {
            machine: machine_id,
        }],
        Instant::now(),
    );

    let fragments = fragment_data(data);
    let mut result = Vec::with_capacity(data.len() * 2);

    let mut rng = StdRng::from_os_rng();

    for fragment in fragments {
        for action in &mut actions {
            if let TriggerAction::SendPadding { timeout, .. } = action {
                let delay_ms = timeout.as_millis() as u64 / 4;
                if delay_ms > 0 {
                    sleep(Duration::from_millis(delay_ms)).await;
                }

                let padding_size = rng.gen_range(0..MAX_PADDING_SIZE);
                if padding_size > 0 {
                    let padding: Vec<u8> = (0..padding_size).map(|_| rng.gen::<u8>()).collect();

                    result.extend_from_slice(&[0xAA, 0xBB]);
                    result.extend_from_slice(&(padding_size as u16).to_be_bytes());
                    result.extend_from_slice(&padding);

                    info!("✅ {} Bytes Padding added", padding_size);
                }
            }
        }

        result.extend_from_slice(&[0xCC, 0xDD]);
        result.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        result.extend_from_slice(&fragment);
    }

    result
}

pub async fn deobfuscate_data(_framework: &MaybenotFramework, data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    if data.len() >= 5 {
        let record_type = data[0];
        let version_major = data[1];
        let version_minor = data[2];

        let is_tls_record =
            record_type == 22 || record_type == 20 || record_type == 21 || record_type == 23;

        let is_tls_version = version_major == 3 && version_minor <= 4;

        if is_tls_record && is_tls_version {
            info!("🔒 Detected TLS traffic, passing through without deobfuscation");
            return data.to_vec();
        }

        if data.len() >= 9 && record_type == 22 {
            info!("🔒 Detected TLS message, passing through without deobfuscation");
            return data.to_vec();
        }
    }

    if data.len() >= 2 {
        let marker = [data[0], data[1]];
        if marker == [0xAA, 0xBB] || marker == [0xCC, 0xDD] || marker == [0xEE, 0xFF] {
            return data.to_vec();
        } else {
            return data.to_vec();
        }
    }

    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;

    while i < data.len() {
        if i + 4 <= data.len() {
            let marker = [data[i], data[i + 1]];

            match marker {
                [0xAA, 0xBB] => {
                    if i + 4 <= data.len() {
                        let size_bytes = [data[i + 2], data[i + 3]];
                        let padding_size = u16::from_be_bytes(size_bytes) as usize;

                        i += 4 + padding_size;
                    } else {
                        break;
                    }
                }

                [0xCC, 0xDD] => {
                    if i + 4 <= data.len() {
                        let size_bytes = [data[i + 2], data[i + 3]];
                        let fragment_size = u16::from_be_bytes(size_bytes) as usize;

                        if i + 4 + fragment_size <= data.len() {
                            result.extend_from_slice(&data[i + 4..i + 4 + fragment_size]);
                            i += 4 + fragment_size;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                [0xEE, 0xFF] => {
                    if i + 4 <= data.len() {
                        let size_bytes = [data[i + 2], data[i + 3]];
                        let dummy_size = u16::from_be_bytes(size_bytes) as usize;

                        i += 4 + dummy_size;
                    } else {
                        break;
                    }
                }

                _ => {
                    result.extend_from_slice(&data[i..]);
                    break;
                }
            }
        } else {
            result.extend_from_slice(&data[i..]);
            break;
        }
    }

    result
}

fn fragment_data(data: &[u8]) -> Vec<Vec<u8>> {
    let mut fragments = Vec::new();
    let mut rng = StdRng::from_os_rng();

    let mut start = 0;
    while start < data.len() {
        let max_size = std::cmp::min(MAX_FRAGMENT_SIZE, data.len() - start);
        let size = if max_size <= MIN_FRAGMENT_SIZE {
            max_size
        } else {
            rng.gen_range(MIN_FRAGMENT_SIZE..=max_size)
        };

        let end = start + size;
        fragments.push(data[start..end].to_vec());
        start = end;
    }

    fragments
}

pub async fn generate_dummy_traffic(framework: &MaybenotFramework) -> Vec<u8> {
    let mut rng = StdRng::from_os_rng();
    let mut fw = framework.lock().await;
    let machine_id = MachineId::from_raw(0);

    let mut actions = fw.trigger_events(
        &[TriggerEvent::PaddingSent {
            machine: machine_id,
        }],
        Instant::now(),
    );

    let mut dummy_size = rng.gen_range(16..64);

    for action in &mut actions {
        if let TriggerAction::SendPadding { timeout, .. } = action {
            dummy_size = (dummy_size + (timeout.as_millis() as usize / 10)).min(128);
        }
    }

    let dummy_data: Vec<u8> = (0..dummy_size).map(|_| rng.gen::<u8>()).collect();

    let mut result = Vec::with_capacity(dummy_size + 4);
    result.extend_from_slice(&[0xEE, 0xFF]);
    result.extend_from_slice(&(dummy_size as u16).to_be_bytes());
    result.extend_from_slice(&dummy_data);

    info!("🔄 {} Bytes Dummy Traffic generated", dummy_size);
    result
}

