mod tests {
    use super::*;

    #[test]
    fn linux_vnet_tun_env_parser_defaults_on() {
        assert!(linux_vnet_tun_enabled_from_env(None));
        assert!(linux_vnet_tun_enabled_from_env(Some("")));
        assert!(!linux_vnet_tun_enabled_from_env(Some("off")));
        assert!(!linux_vnet_tun_enabled_from_env(Some("0")));
        assert!(linux_vnet_tun_enabled_from_env(Some("1")));
        assert!(linux_vnet_tun_enabled_from_env(Some("true")));
    }

    #[test]
    fn linux_vnet_plain_read_strips_virtio_header() {
        let packet = ipv6_tcp_packet(1000, 16, LINUX_TCP_FLAG_PSH);
        let mut frame = vec![0u8; LINUX_VIRTIO_NET_HDR_LEN + packet.len()];
        LinuxVirtioNetHdr {
            flags: 0,
            gso_type: LINUX_VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
        }
        .encode(&mut frame[..LINUX_VIRTIO_NET_HDR_LEN]);
        frame[LINUX_VIRTIO_NET_HDR_LEN..].copy_from_slice(&packet);

        let mut pending = VecDeque::new();
        collect_linux_vnet_packets(&mut frame, &mut pending).expect("plain vnet frame");
        assert_eq!(pending.len(), 1);
        let collected = pending.pop_front().unwrap();
        assert_eq!(collected, packet);
        assert!(
            collected.capacity()
                >= collected.len() + super::super::TUN_OUTBOUND_PACKET_TAIL_RESERVE
        );
    }

    #[test]
    fn linux_vnet_tcpv6_gso_read_splits_into_checked_segments() {
        let packet = ipv6_tcp_packet(1000, 2400, LINUX_TCP_FLAG_PSH);
        let mut frame = vec![0u8; LINUX_VIRTIO_NET_HDR_LEN + packet.len()];
        LinuxVirtioNetHdr {
            flags: LINUX_VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: LINUX_VIRTIO_NET_HDR_GSO_TCPV6,
            hdr_len: 60,
            gso_size: 1200,
            csum_start: 40,
            csum_offset: 16,
        }
        .encode(&mut frame[..LINUX_VIRTIO_NET_HDR_LEN]);
        frame[LINUX_VIRTIO_NET_HDR_LEN..].copy_from_slice(&packet);

        let mut pending = VecDeque::new();
        collect_linux_vnet_packets(&mut frame, &mut pending).expect("tcpv6 gso frame");
        assert_eq!(pending.len(), 2);
        let first = pending.pop_front().unwrap();
        let second = pending.pop_front().unwrap();

        assert_eq!(first.len(), 40 + 20 + 1200);
        assert_eq!(second.len(), 40 + 20 + 1200);
        assert!(first.capacity() >= first.len() + super::super::TUN_OUTBOUND_PACKET_TAIL_RESERVE);
        assert!(second.capacity() >= second.len() + super::super::TUN_OUTBOUND_PACKET_TAIL_RESERVE);
        assert_eq!(u16::from_be_bytes([first[4], first[5]]), 20 + 1200);
        assert_eq!(u16::from_be_bytes([second[4], second[5]]), 20 + 1200);
        assert_eq!(
            u32::from_be_bytes([first[44], first[45], first[46], first[47]]),
            1000
        );
        assert_eq!(
            u32::from_be_bytes([second[44], second[45], second[46], second[47]]),
            2200
        );
        assert_eq!(first[53] & LINUX_TCP_FLAG_PSH, 0);
        assert_ne!(second[53] & LINUX_TCP_FLAG_PSH, 0);
        assert_eq!(ipv6_transport_sum(&first), 0xffff);
        assert_eq!(ipv6_transport_sum(&second), 0xffff);
    }

    #[test]
    fn linux_vnet_tcpv6_gro_write_coalesces_adjacent_segments() {
        let first = ipv6_tcp_packet(1000, 800, LINUX_TCP_FLAG_ACK);
        let second = ipv6_tcp_packet(1800, 600, LINUX_TCP_FLAG_ACK | LINUX_TCP_FLAG_PSH);
        let packets = vec![first, second];
        let frames = prepared_write_frame_bytes(&packets);
        assert_eq!(frames.len(), 1);

        let hdr = LinuxVirtioNetHdr::decode(&frames[0]).expect("virtio header");
        assert_eq!(hdr.flags, LINUX_VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(hdr.gso_type, LINUX_VIRTIO_NET_HDR_GSO_TCPV6);
        assert_eq!(hdr.hdr_len, 60);
        assert_eq!(hdr.gso_size, 800);
        assert_eq!(hdr.csum_start, 40);
        assert_eq!(hdr.csum_offset, 16);

        let packet = &frames[0][LINUX_VIRTIO_NET_HDR_LEN..];
        assert_eq!(packet.len(), 40 + 20 + 1400);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 20 + 1400);
        assert_ne!(packet[53] & LINUX_TCP_FLAG_PSH, 0);

        let pseudo = linux_vnet_pseudo_header_sum(
            LINUX_IPPROTO_TCP,
            &packet[8..24],
            &packet[24..40],
            (packet.len() - 40) as u16,
        );
        let expected_partial = !linux_vnet_checksum(&[], pseudo);
        assert_eq!(
            u16::from_be_bytes([packet[56], packet[57]]),
            expected_partial
        );
    }

    fn prepared_write_frame_bytes(packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let packet_slices: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
        let mut preparer = LinuxVnetWritePreparer::new();
        preparer.prepare(packet_slices.iter().copied());
        preparer
            .frames
            .iter()
            .map(|frame| match frame {
                LinuxVnetPreparedWriteFrame::RawPacket(packet_index) => {
                    let mut bytes = vec![0u8; LINUX_VIRTIO_NET_HDR_LEN];
                    bytes.extend_from_slice(packet_slices[*packet_index]);
                    bytes
                }
                LinuxVnetPreparedWriteFrame::Vectored(frame_index) => {
                    let frame = &preparer.vectored_frames[*frame_index];
                    let mut bytes = Vec::new();
                    bytes.extend_from_slice(&frame.virtio_header);
                    let first_packet = packet_slices[frame.first_packet_index];
                    if frame.first_header.is_empty() {
                        bytes.extend_from_slice(first_packet);
                    } else {
                        bytes.extend_from_slice(&frame.first_header);
                        bytes.extend_from_slice(&first_packet[frame.first_payload_offset..]);
                    }
                    for segment in &frame.payload_segments {
                        bytes.extend_from_slice(
                            &packet_slices[segment.packet_index][segment.payload_offset..],
                        );
                    }
                    bytes
                }
            })
            .collect()
    }

    fn ipv6_tcp_packet(seq: u32, payload_len: usize, flags: u8) -> Vec<u8> {
        let total_len = 40 + 20 + payload_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((20 + payload_len) as u16).to_be_bytes());
        packet[6] = LINUX_IPPROTO_TCP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let tcp = &mut packet[40..60];
        tcp[0..2].copy_from_slice(&443u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&45172u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&7000u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        for (index, byte) in packet[60..].iter_mut().enumerate() {
            *byte = (index & 0xff) as u8;
        }
        let pseudo = linux_vnet_pseudo_header_sum(
            LINUX_IPPROTO_TCP,
            &packet[8..24],
            &packet[24..40],
            (20 + payload_len) as u16,
        );
        let checksum = !linux_vnet_checksum(&packet[40..], pseudo);
        packet[56..58].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn ipv6_transport_sum(packet: &[u8]) -> u16 {
        let transport_len = packet.len() - 40;
        let pseudo = linux_vnet_pseudo_header_sum(
            packet[6],
            &packet[8..24],
            &packet[24..40],
            transport_len as u16,
        );
        linux_vnet_checksum(&packet[40..], pseudo)
    }
}
