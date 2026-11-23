// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;

use socket2::{SockRef, Socket};
use tracing::debug;

use crate::features::boot_phase::BootPhase;

/// Six-bit DSCP value stored in a TOS or traffic-class byte.
pub type DscpValue = u8;

/// Applies configured DSCP and ECN policy by boot phase.
pub struct DscpManager {
    /// Phase-to-DSCP mapping.
    phase_map: HashMap<BootPhase, DscpValue>,
    /// Whether emitted traffic advertises ECN capability.
    ecn_enabled: bool,
}

impl DscpManager {
    /// Builds phase mappings, discarding invalid DSCP values above 63.
    ///
    /// When ECN is enabled, generated TOS bytes advertise ECT(0).
    pub fn new(phase_dscp: &HashMap<String, u8>, ecn_enabled: bool) -> Self {
        let phase_map = phase_dscp
            .iter()
            // Validate DSCP values are within valid 6-bit range (0-63)
            .filter(|&(_, &dscp)| dscp <= 63)
            .map(|(name, &dscp)| (BootPhase::from_name(name), dscp))
            .collect();

        Self {
            phase_map,
            ecn_enabled,
        }
    }

    /// Get the TOS byte value for a socket based on the boot phase.
    /// TOS byte = (DSCP << 2) | ECN bits
    pub fn tos_value(&self, phase: &BootPhase) -> u8 {
        let dscp = self.phase_map.get(phase).copied().unwrap_or(0);

        let ecn_bits = if self.ecn_enabled { 0b10 } else { 0 }; // ECT(0)
        (dscp << 2) | ecn_bits
    }

    /// Apply the phase's DSCP marking to an owned socket.
    pub fn apply_to_socket(&self, socket: &Socket, phase: &BootPhase) -> io::Result<()> {
        let tos = self.tos_value(phase) as u32;
        if tos == 0 {
            return Ok(());
        }
        socket.set_tos_v4(tos)?;
        debug!(phase = ?phase, tos, "Applied DSCP marking");
        Ok(())
    }

    /// Apply the phase's DSCP marking to a borrowed socket.
    pub fn apply_to_sock_ref(&self, socket: SockRef<'_>, phase: &BootPhase) -> io::Result<()> {
        let tos = self.tos_value(phase) as u32;
        if tos == 0 {
            return Ok(());
        }
        socket.set_tos_v4(tos)?;
        debug!(phase = ?phase, tos, "Applied DSCP marking via SockRef");
        Ok(())
    }

    /// Apply the phase's DSCP marking to a socket bound to `local_ip`.
    ///
    /// IPv4 sockets use `IP_TOS`. IPv6 sockets use `IPV6_TCLASS`, which this
    /// build can set only on Linux; elsewhere an IPv6 mark is an error, never a
    /// silent no-op.
    pub fn apply_to_sock_ref_for(
        &self,
        socket: SockRef<'_>,
        local_ip: IpAddr,
        phase: &BootPhase,
    ) -> io::Result<()> {
        if local_ip.is_ipv4() {
            return self.apply_to_sock_ref(socket, phase);
        }
        let tos = self.tos_value(phase);
        if tos == 0 {
            return Ok(());
        }
        set_ipv6_traffic_class(&socket, tos)?;
        debug!(phase = ?phase, tos, "Applied IPv6 DSCP marking");
        Ok(())
    }

    /// Return whether an incoming TOS byte carries an ECN congestion mark.
    pub fn check_ecn_congestion(&self, tos_byte: u8) -> bool {
        self.ecn_enabled && (tos_byte & 0b11) == 0b11 // CE = both ECN bits set
    }

    /// Returns whether this manager writes and interprets ECN bits.
    pub fn is_ecn_enabled(&self) -> bool {
        self.ecn_enabled
    }
}

#[cfg(target_os = "linux")]
fn set_ipv6_traffic_class(socket: &Socket, value: u8) -> io::Result<()> {
    rustix::net::sockopt::set_ipv6_tclass(socket, u32::from(value)).map_err(io::Error::from)
}

#[cfg(not(target_os = "linux"))]
fn set_ipv6_traffic_class(_socket: &Socket, _value: u8) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IPv6 traffic-class marking requires Linux",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dscp_manager() -> DscpManager {
        let mut phase_dscp = HashMap::new();
        phase_dscp.insert("PXE_ROM".into(), 46);
        phase_dscp.insert("KERNEL".into(), 34);
        phase_dscp.insert("OS_IMAGE".into(), 18);
        DscpManager::new(&phase_dscp, false)
    }

    #[test]
    fn test_tos_value_pxe_rom() {
        let manager = test_dscp_manager();
        let tos = manager.tos_value(&BootPhase::PxeRom);
        assert_eq!(tos, 46 << 2); // DSCP 46 (EF) without ECN
    }

    #[test]
    fn test_tos_value_kernel() {
        let manager = test_dscp_manager();
        let tos = manager.tos_value(&BootPhase::Kernel);
        assert_eq!(tos, 34 << 2); // DSCP 34 (AF41)
    }

    #[test]
    fn test_tos_value_unknown_phase() {
        let manager = test_dscp_manager();
        let tos = manager.tos_value(&BootPhase::Unknown);
        assert_eq!(tos, 0); // Default when phase not mapped
    }

    #[test]
    fn test_tos_value_with_ecn() {
        let mut phase_dscp = HashMap::new();
        phase_dscp.insert("PXE_ROM".into(), 46);
        let manager = DscpManager::new(&phase_dscp, true);
        let tos = manager.tos_value(&BootPhase::PxeRom);
        assert_eq!(tos, (46 << 2) | 0b10); // ECT(0)
    }

    #[test]
    fn test_ecn_congestion_detection() {
        let mut phase_dscp = HashMap::new();
        phase_dscp.insert("PXE_ROM".into(), 46);
        let manager = DscpManager::new(&phase_dscp, true);

        // CE (Congestion Experienced) = both ECN bits set
        assert!(manager.check_ecn_congestion(0b11));
        // ECT(0) = not congestion
        assert!(!manager.check_ecn_congestion(0b10));
        // No ECN bits
        assert!(!manager.check_ecn_congestion(0b00));
    }

    #[test]
    fn test_ecn_disabled() {
        let manager = test_dscp_manager();
        assert!(!manager.is_ecn_enabled());
        assert!(!manager.check_ecn_congestion(0b11));
    }

    #[test]
    fn test_dscp_rejects_invalid_values() {
        let mut phase_dscp = HashMap::new();
        phase_dscp.insert("PXE_ROM".into(), 46); // valid (0-63)
        phase_dscp.insert("KERNEL".into(), 64); // invalid (> 63)
        phase_dscp.insert("OS_IMAGE".into(), 255); // invalid
        let manager = DscpManager::new(&phase_dscp, false);

        assert_eq!(manager.tos_value(&BootPhase::PxeRom), 46 << 2);
        assert_eq!(manager.tos_value(&BootPhase::Kernel), 0);
        assert_eq!(manager.tos_value(&BootPhase::OsImage), 0);
    }

    #[test]
    fn test_dscp_sock_ref_apply() {
        // Bind a real UDP socket, apply DSCP via SockRef, read TOS back
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket2_ref = SockRef::from(&std_socket);
        let mut phase_dscp = HashMap::new();
        phase_dscp.insert("PXE_ROM".into(), 46u8);
        phase_dscp.insert("KERNEL".into(), 34u8);
        phase_dscp.insert("OS_IMAGE".into(), 18u8);
        let manager = DscpManager::new(&phase_dscp, false);

        // PXE_ROM: DSCP 46 → TOS = 46 << 2 = 184
        manager
            .apply_to_sock_ref(SockRef::from(&std_socket), &BootPhase::PxeRom)
            .unwrap();
        assert_eq!(socket2_ref.tos_v4().unwrap(), 184);

        // KERNEL: DSCP 34 → TOS = 34 << 2 = 136
        manager
            .apply_to_sock_ref(SockRef::from(&std_socket), &BootPhase::Kernel)
            .unwrap();
        assert_eq!(SockRef::from(&std_socket).tos_v4().unwrap(), 136);

        // OS_IMAGE: DSCP 18 → TOS = 18 << 2 = 72
        manager
            .apply_to_sock_ref(SockRef::from(&std_socket), &BootPhase::OsImage)
            .unwrap();
        assert_eq!(SockRef::from(&std_socket).tos_v4().unwrap(), 72);
    }

    #[test]
    fn test_dscp_accepts_boundary_values() {
        let mut phase_dscp = HashMap::new();
        phase_dscp.insert("PXE_ROM".into(), 0); // minimum valid
        phase_dscp.insert("KERNEL".into(), 63); // maximum valid
        let manager = DscpManager::new(&phase_dscp, false);

        assert_eq!(manager.tos_value(&BootPhase::PxeRom), 0);
        assert_eq!(manager.tos_value(&BootPhase::Kernel), 63 << 2);
    }

    #[test]
    fn zero_tos_does_not_replace_an_existing_socket_mark() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket_ref = SockRef::from(&socket);
        socket_ref.set_tos_v4(0x48).unwrap();
        let manager = DscpManager::new(&HashMap::new(), false);

        manager
            .apply_to_sock_ref(SockRef::from(&socket), &BootPhase::Unknown)
            .unwrap();

        assert_eq!(socket_ref.tos_v4().unwrap(), 0x48);
    }

    fn ipv6_loopback_socket() -> Option<std::net::UdpSocket> {
        std::net::UdpSocket::bind("[::1]:0").ok()
    }

    #[test]
    fn family_aware_apply_keeps_the_ipv4_mark() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let manager = test_dscp_manager();

        manager
            .apply_to_sock_ref_for(
                SockRef::from(&socket),
                IpAddr::from([127, 0, 0, 1]),
                &BootPhase::Kernel,
            )
            .unwrap();

        assert_eq!(SockRef::from(&socket).tos_v4().unwrap(), 34 << 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ipv6_sockets_receive_the_phase_traffic_class() {
        let Some(socket) = ipv6_loopback_socket() else {
            return;
        };
        let mut phase_dscp = HashMap::new();
        phase_dscp.insert("PXE_ROM".into(), 46u8);
        phase_dscp.insert("KERNEL".into(), 63u8);
        let plain = DscpManager::new(&phase_dscp, false);
        let ecn = DscpManager::new(&phase_dscp, true);
        let local = IpAddr::from(std::net::Ipv6Addr::LOCALHOST);

        plain
            .apply_to_sock_ref_for(SockRef::from(&socket), local, &BootPhase::PxeRom)
            .unwrap();
        assert_eq!(rustix::net::sockopt::ipv6_tclass(&socket).unwrap(), 184);

        plain
            .apply_to_sock_ref_for(SockRef::from(&socket), local, &BootPhase::Kernel)
            .unwrap();
        assert_eq!(rustix::net::sockopt::ipv6_tclass(&socket).unwrap(), 63 << 2);

        ecn.apply_to_sock_ref_for(SockRef::from(&socket), local, &BootPhase::PxeRom)
            .unwrap();
        assert_eq!(
            rustix::net::sockopt::ipv6_tclass(&socket).unwrap(),
            (46 << 2) | 0b10
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn zero_ipv6_mark_does_not_replace_an_existing_traffic_class() {
        let Some(socket) = ipv6_loopback_socket() else {
            return;
        };
        rustix::net::sockopt::set_ipv6_tclass(&socket, 0x48).unwrap();
        let manager = DscpManager::new(&HashMap::new(), false);

        manager
            .apply_to_sock_ref_for(
                SockRef::from(&socket),
                IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
                &BootPhase::Unknown,
            )
            .unwrap();

        assert_eq!(rustix::net::sockopt::ipv6_tclass(&socket).unwrap(), 0x48);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn ipv6_marking_is_rejected_where_it_cannot_be_applied() {
        let Some(socket) = ipv6_loopback_socket() else {
            return;
        };
        let manager = test_dscp_manager();
        let local = IpAddr::from(std::net::Ipv6Addr::LOCALHOST);

        let error = manager
            .apply_to_sock_ref_for(SockRef::from(&socket), local, &BootPhase::PxeRom)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);

        manager
            .apply_to_sock_ref_for(SockRef::from(&socket), local, &BootPhase::Unknown)
            .unwrap();
    }
}
