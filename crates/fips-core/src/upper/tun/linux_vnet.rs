use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

pub(super) const LINUX_VIRTIO_NET_HDR_LEN: usize = 10;

const LINUX_VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 0x01;
const LINUX_VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const LINUX_VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
const LINUX_VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;
const LINUX_VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;
const LINUX_TCP_FLAGS_OFFSET: usize = 13;
const LINUX_TCP_FLAG_FIN: u8 = 0x01;
const LINUX_TCP_FLAG_PSH: u8 = 0x08;
const LINUX_TCP_FLAG_ACK: u8 = 0x10;
const LINUX_IPPROTO_TCP: u8 = 6;
const LINUX_IPPROTO_UDP: u8 = 17;
const LINUX_IPV6_SRC_ADDR_OFFSET: usize = 8;
const LINUX_VNET_FRAME_BUFFER_LEN: usize = LINUX_VIRTIO_NET_HDR_LEN + u16::MAX as usize;
const LINUX_IOV_MAX: usize = 1024;

#[repr(C)]
union LinuxIfReqIfru {
    ifru_flags: libc::c_short,
}

#[repr(C)]
struct LinuxIfReq {
    ifr_name: [libc::c_uchar; libc::IFNAMSIZ],
    ifr_ifru: LinuxIfReqIfru,
}

pub(super) struct LinuxVnetTun {
    file: File,
    name: String,
    pending: VecDeque<Vec<u8>>,
}

impl LinuxVnetTun {
    pub(super) fn create(name: &str) -> io::Result<Self> {
        if name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid Linux TUN interface name '{name}'"),
            ));
        }

        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        match configure_linux_vnet_fd(fd, name) {
            Ok(()) => Ok(Self {
                file: unsafe { File::from_raw_fd(fd) },
                name: name.to_string(),
                pending: VecDeque::new(),
            }),
            Err(error) => {
                unsafe {
                    libc::close(fd);
                }
                Err(error)
            }
        }
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn read_buffer_len(&self) -> usize {
        LINUX_VNET_FRAME_BUFFER_LEN
    }

    pub(super) fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(packet) = self.pending.pop_front() {
            return copy_packet_to_read_buffer(packet, buf);
        }

        let read_len = unsafe {
            libc::read(
                self.file.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if read_len < 0 {
            return Err(io::Error::last_os_error());
        }
        if read_len == 0 {
            return Ok(0);
        }

        crate::perf_profile::record_tun_read_frame(read_len as usize);
        collect_linux_vnet_packets(&mut buf[..read_len as usize], &mut self.pending)?;
        if let Some(packet) = self.pending.pop_front() {
            copy_packet_to_read_buffer(packet, buf)
        } else {
            Ok(0)
        }
    }

    pub(super) fn read_packets_into(
        &mut self,
        buf: &mut [u8],
        packets: &mut Vec<Vec<u8>>,
    ) -> io::Result<usize> {
        let before_len = packets.len();
        while let Some(packet) = self.pending.pop_front() {
            packets.push(packet);
        }
        if packets.len() != before_len {
            return Ok(packets.len() - before_len);
        }

        let read_len = unsafe {
            libc::read(
                self.file.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if read_len < 0 {
            return Err(io::Error::last_os_error());
        }
        if read_len == 0 {
            return Ok(0);
        }

        crate::perf_profile::record_tun_read_frame(read_len as usize);
        collect_linux_vnet_packets(&mut buf[..read_len as usize], packets)?;
        Ok(packets.len() - before_len)
    }
}

impl AsRawFd for LinuxVnetTun {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

fn configure_linux_vnet_fd(fd: RawFd, name: &str) -> io::Result<()> {
    let mut ifr = LinuxIfReq {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_ifru: LinuxIfReqIfru {
            ifru_flags: (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as libc::c_short,
        },
    };
    let name_bytes = name.as_bytes();
    ifr.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

    let rc = unsafe { libc::ioctl(fd, libc::TUNSETIFF as _, &ifr) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let tcp_offloads = libc::TUN_F_CSUM | libc::TUN_F_TSO6;
    let rc = unsafe { libc::ioctl(fd, libc::TUNSETOFFLOAD as _, tcp_offloads) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    // UDP segmentation offload was added after the original TUN offload API.
    // Linux exposes UDP_L4 as one feature and requires USO4 and USO6 to be
    // toggled together, even though this TUN carries only FIPS IPv6 packets.
    // Keep TCPv6 vnet usable when an older kernel rejects the UDP flags.
    let udp_offloads = tcp_offloads | libc::TUN_F_USO4 | libc::TUN_F_USO6;
    let udp_gso = unsafe { libc::ioctl(fd, libc::TUNSETOFFLOAD as _, udp_offloads) } >= 0;

    tracing::debug!(name, udp_gso, "Linux vnet TUN enabled");
    Ok(())
}

pub(super) fn linux_vnet_tun_enabled() -> bool {
    static VALUE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        linux_vnet_tun_enabled_from_env(std::env::var("FIPS_LINUX_TUN_VNET").ok().as_deref())
    })
}

fn linux_vnet_tun_enabled_from_env(value: Option<&str>) -> bool {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    !(value == "0"
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("off"))
}

fn copy_packet_to_read_buffer(packet: Vec<u8>, buf: &mut [u8]) -> io::Result<usize> {
    if packet.len() > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux vnet TUN packet exceeds read buffer",
        ));
    }
    let len = packet.len();
    buf[..len].copy_from_slice(&packet);
    Ok(len)
}

fn owned_tun_packet_with_tail_room(packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(packet.len() + super::TUN_OUTBOUND_PACKET_TAIL_RESERVE);
    out.extend_from_slice(packet);
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxVirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}

impl LinuxVirtioNetHdr {
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < LINUX_VIRTIO_NET_HDR_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short virtio net header",
            ));
        }
        Ok(Self {
            flags: bytes[0],
            gso_type: bytes[1],
            hdr_len: u16::from_ne_bytes([bytes[2], bytes[3]]),
            gso_size: u16::from_ne_bytes([bytes[4], bytes[5]]),
            csum_start: u16::from_ne_bytes([bytes[6], bytes[7]]),
            csum_offset: u16::from_ne_bytes([bytes[8], bytes[9]]),
        })
    }

    fn encode(self, bytes: &mut [u8]) {
        bytes[0] = self.flags;
        bytes[1] = self.gso_type;
        bytes[2..4].copy_from_slice(&self.hdr_len.to_ne_bytes());
        bytes[4..6].copy_from_slice(&self.gso_size.to_ne_bytes());
        bytes[6..8].copy_from_slice(&self.csum_start.to_ne_bytes());
        bytes[8..10].copy_from_slice(&self.csum_offset.to_ne_bytes());
    }
}

trait LinuxVnetPacketSink {
    fn reserve_packets(&mut self, additional: usize);
    fn push_packet(&mut self, packet: Vec<u8>);
}

impl LinuxVnetPacketSink for VecDeque<Vec<u8>> {
    fn reserve_packets(&mut self, additional: usize) {
        self.reserve(additional);
    }

    fn push_packet(&mut self, packet: Vec<u8>) {
        self.push_back(packet);
    }
}

impl LinuxVnetPacketSink for Vec<Vec<u8>> {
    fn reserve_packets(&mut self, additional: usize) {
        self.reserve(additional);
    }

    fn push_packet(&mut self, packet: Vec<u8>) {
        self.push(packet);
    }
}

fn collect_linux_vnet_packets(
    frame: &mut [u8],
    packets: &mut impl LinuxVnetPacketSink,
) -> io::Result<()> {
    let hdr = LinuxVirtioNetHdr::decode(frame)?;
    let packet = &mut frame[LINUX_VIRTIO_NET_HDR_LEN..];
    let gso_type = hdr.gso_type & !LINUX_VIRTIO_NET_HDR_GSO_ECN;

    if gso_type == LINUX_VIRTIO_NET_HDR_GSO_NONE {
        if hdr.flags & LINUX_VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
            linux_vnet_gso_none_checksum(packet, hdr.csum_start, hdr.csum_offset)?;
        }
        packets.push_packet(owned_tun_packet_with_tail_room(packet));
        return Ok(());
    }

    if hdr.gso_type & LINUX_VIRTIO_NET_HDR_GSO_ECN != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux vnet TUN GSO ECN packets are not supported",
        ));
    }
    if gso_type != LINUX_VIRTIO_NET_HDR_GSO_TCPV6 && gso_type != LINUX_VIRTIO_NET_HDR_GSO_UDP_L4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported Linux vnet TUN GSO type {gso_type}"),
        ));
    }
    if hdr.gso_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux vnet TUN GSO packet has zero segment size",
        ));
    }
    if packet.first().map(|byte| byte >> 4) != Some(6) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux vnet TCPv6 GSO frame does not contain an IPv6 packet",
        ));
    }

    let mut hdr = hdr;
    if gso_type == LINUX_VIRTIO_NET_HDR_GSO_UDP_L4 {
        if hdr.csum_offset != 6 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Linux vnet TUN UDP GSO frame has invalid checksum offset",
            ));
        }
        hdr.hdr_len = hdr.csum_start.saturating_add(8);
    } else {
        let tcp_data_offset_at = usize::from(hdr.csum_start).saturating_add(12);
        let Some(&data_offset_byte) = packet.get(tcp_data_offset_at) else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Linux vnet TUN TCP GSO packet is too short",
            ));
        };
        let tcp_header_len = u16::from(data_offset_byte >> 4) * 4;
        if !(20..=60).contains(&tcp_header_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Linux vnet TUN TCP header length {tcp_header_len}"),
            ));
        }
        hdr.hdr_len = hdr.csum_start.saturating_add(tcp_header_len);
    }

    linux_vnet_ipv6_gso_split(packet, hdr, gso_type, packets)
}

fn linux_vnet_gso_none_checksum(
    packet: &mut [u8],
    csum_start: u16,
    csum_offset: u16,
) -> io::Result<()> {
    let csum_start = usize::from(csum_start);
    let csum_at = csum_start.saturating_add(usize::from(csum_offset));
    if csum_start >= packet.len() || csum_at + 1 >= packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Linux vnet TUN checksum bounds",
        ));
    }
    let initial = u16::from_be_bytes([packet[csum_at], packet[csum_at + 1]]);
    packet[csum_at] = 0;
    packet[csum_at + 1] = 0;
    let checksum = !linux_vnet_checksum(&packet[csum_start..], u64::from(initial));
    packet[csum_at..csum_at + 2].copy_from_slice(&checksum.to_be_bytes());
    Ok(())
}

fn linux_vnet_ipv6_gso_split(
    packet: &mut [u8],
    hdr: LinuxVirtioNetHdr,
    gso_type: u8,
    packets: &mut impl LinuxVnetPacketSink,
) -> io::Result<()> {
    let ip_header_len = usize::from(hdr.csum_start);
    let hdr_len = usize::from(hdr.hdr_len);
    let transport_csum_at = usize::from(hdr.csum_start + hdr.csum_offset);
    if packet.len() < hdr_len || hdr_len < ip_header_len || transport_csum_at + 1 >= packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Linux vnet TUN GSO header bounds",
        ));
    }
    if LINUX_IPV6_SRC_ADDR_OFFSET + 32 > packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux vnet TUN GSO packet is too short for IPv6 addresses",
        ));
    }

    packet[transport_csum_at] = 0;
    packet[transport_csum_at + 1] = 0;

    let protocol = if gso_type == LINUX_VIRTIO_NET_HDR_GSO_TCPV6 {
        LINUX_IPPROTO_TCP
    } else {
        LINUX_IPPROTO_UDP
    };
    let first_tcp_seq = if protocol == LINUX_IPPROTO_TCP {
        let seq_at = ip_header_len.saturating_add(4);
        u32::from_be_bytes([
            packet[seq_at],
            packet[seq_at + 1],
            packet[seq_at + 2],
            packet[seq_at + 3],
        ])
    } else {
        0
    };

    let src = &packet[LINUX_IPV6_SRC_ADDR_OFFSET..LINUX_IPV6_SRC_ADDR_OFFSET + 16];
    let dst = &packet[LINUX_IPV6_SRC_ADDR_OFFSET + 16..LINUX_IPV6_SRC_ADDR_OFFSET + 32];
    let payload_len = packet.len() - hdr_len;
    let gso_size = usize::from(hdr.gso_size);
    packets.reserve_packets(payload_len.div_ceil(gso_size));

    let mut next_segment_data_at = hdr_len;
    let mut count = 0usize;
    while next_segment_data_at < packet.len() {
        let next_segment_end = (next_segment_data_at + gso_size).min(packet.len());
        let segment_data_len = next_segment_end - next_segment_data_at;
        let total_len = hdr_len + segment_data_len;
        if total_len > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Linux vnet TUN GSO segment exceeds packet length limit",
            ));
        }

        let mut out = Vec::with_capacity(total_len + super::TUN_OUTBOUND_PACKET_TAIL_RESERVE);
        out.extend_from_slice(&packet[..hdr_len]);
        out.extend_from_slice(&packet[next_segment_data_at..next_segment_end]);
        out[4..6].copy_from_slice(&((total_len - ip_header_len) as u16).to_be_bytes());

        if protocol == LINUX_IPPROTO_TCP {
            let tcp_seq = first_tcp_seq.wrapping_add(u32::from(hdr.gso_size) * count as u32);
            out[ip_header_len + 4..ip_header_len + 8].copy_from_slice(&tcp_seq.to_be_bytes());
            if next_segment_end != packet.len() {
                out[ip_header_len + LINUX_TCP_FLAGS_OFFSET] &=
                    !(LINUX_TCP_FLAG_FIN | LINUX_TCP_FLAG_PSH);
            }
        } else {
            let udp_len = total_len - ip_header_len;
            out[ip_header_len + 4..ip_header_len + 6]
                .copy_from_slice(&(udp_len as u16).to_be_bytes());
        }

        let transport_len = total_len - ip_header_len;
        let pseudo_sum = linux_vnet_pseudo_header_sum(protocol, src, dst, transport_len as u16);
        let mut transport_checksum = !linux_vnet_checksum(&out[ip_header_len..], pseudo_sum);
        if protocol == LINUX_IPPROTO_UDP && transport_checksum == 0 {
            transport_checksum = u16::MAX;
        }
        let out_csum_at = ip_header_len + usize::from(hdr.csum_offset);
        out[out_csum_at..out_csum_at + 2].copy_from_slice(&transport_checksum.to_be_bytes());

        packets.push_packet(out);
        count += 1;
        next_segment_data_at = next_segment_end;
    }

    Ok(())
}

fn linux_vnet_pseudo_header_sum(protocol: u8, src: &[u8], dst: &[u8], total_len: u16) -> u64 {
    let mut sum = linux_vnet_add_words(0, src);
    sum = linux_vnet_add_words(sum, dst);
    sum += u64::from(protocol);
    sum += u64::from(total_len);
    sum
}

fn linux_vnet_checksum(bytes: &[u8], initial: u64) -> u16 {
    let mut sum = linux_vnet_add_words(initial, bytes);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn linux_vnet_add_words(mut sum: u64, bytes: &[u8]) -> u64 {
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_be_bytes(chunk.try_into().expect("chunk is 8 bytes"));
        sum += (word >> 48) + ((word >> 32) & 0xffff) + ((word >> 16) & 0xffff) + (word & 0xffff);
    }

    let mut tail = chunks.remainder().chunks_exact(2);
    for chunk in &mut tail {
        sum += u64::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = tail.remainder().first() {
        sum += u64::from(byte) << 8;
    }
    sum
}

#[derive(Clone, Copy)]
struct LinuxVnetPacketRef {
    ptr: *const u8,
    len: usize,
}

impl LinuxVnetPacketRef {
    fn new(packet: &[u8]) -> Self {
        Self {
            ptr: packet.as_ptr(),
            len: packet.len(),
        }
    }

    fn with_slice<T>(self, f: impl FnOnce(&[u8]) -> T) -> T {
        let packet = unsafe { std::slice::from_raw_parts(self.ptr, self.len) };
        f(packet)
    }

    fn len_from_offset(self, offset: usize) -> usize {
        self.len
            .checked_sub(offset)
            .expect("prepared Linux vnet packet offset must be in bounds")
    }

    fn iovec_from_offset(self, offset: usize) -> libc::iovec {
        let len = self.len_from_offset(offset);
        libc::iovec {
            iov_base: unsafe { self.ptr.add(offset) } as *mut libc::c_void,
            iov_len: len,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxVnetPayloadSegment {
    packet_index: usize,
    payload_offset: usize,
}

struct LinuxVnetWriteFrame {
    virtio_header: [u8; LINUX_VIRTIO_NET_HDR_LEN],
    first_header: Vec<u8>,
    first_packet_index: usize,
    first_payload_offset: usize,
    payload_segments: Vec<LinuxVnetPayloadSegment>,
    tcp6_gro: Option<LinuxVnetTcp6GroState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinuxVnetPreparedWriteFrame {
    RawPacket(usize),
    Vectored(usize),
}

#[derive(Clone, Debug)]
struct LinuxVnetTcp6GroState {
    tcp_header_len: usize,
    gso_size: usize,
    payload_len: usize,
    next_seq: u32,
    psh_set: bool,
    flow: LinuxVnetTcp6GroFlow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LinuxVnetTcp6GroFlow {
    version_tc_flow: [u8; 4],
    next_header: u8,
    hop_limit: u8,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
    ack: u32,
    tcp_options_len: u8,
    tcp_options: [u8; 40],
}

#[derive(Clone, Debug)]
struct LinuxVnetTcp6GroCandidate {
    tcp_header_len: usize,
    payload_len: usize,
    seq: u32,
    psh_set: bool,
    flow: LinuxVnetTcp6GroFlow,
}

pub(super) struct LinuxVnetWritePreparer {
    frames: Vec<LinuxVnetPreparedWriteFrame>,
    vectored_frames: Vec<LinuxVnetWriteFrame>,
    vectored_frame_count: usize,
    packet_refs: Vec<LinuxVnetPacketRef>,
    write_iov: Vec<libc::iovec>,
    open_tcp6_flows: Vec<(LinuxVnetTcp6GroFlow, usize)>,
}

// The scratch iovec and packet-ref vectors are owned by one TUN writer thread
// and are only populated for a synchronous prepare/write pass.
unsafe impl Send for LinuxVnetWritePreparer {}

impl LinuxVnetWritePreparer {
    pub(super) fn new() -> Self {
        Self {
            frames: Vec::new(),
            vectored_frames: Vec::new(),
            vectored_frame_count: 0,
            packet_refs: Vec::new(),
            write_iov: Vec::new(),
            open_tcp6_flows: Vec::new(),
        }
    }

    fn prepare<'a, I>(&mut self, packets: I)
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        self.frames.clear();
        self.open_tcp6_flows.clear();
        self.vectored_frame_count = 0;
        self.packet_refs.clear();
        self.packet_refs
            .extend(packets.into_iter().map(LinuxVnetPacketRef::new));

        self.frames.reserve(self.packet_refs.len());
        self.open_tcp6_flows.reserve(self.packet_refs.len());
        for packet_index in 0..self.packet_refs.len() {
            if let Some(candidate) =
                self.packet_refs[packet_index].with_slice(linux_vnet_tcp6_gro_candidate)
            {
                if let Some((_, owned_index)) = self
                    .open_tcp6_flows
                    .iter()
                    .rfind(|(flow, _)| *flow == candidate.flow)
                    && linux_vnet_try_tcp6_gro_append_with_candidate(
                        &mut self.vectored_frames[*owned_index],
                        packet_index,
                        &candidate,
                    )
                {
                    continue;
                }

                let flow = candidate.flow.clone();
                let owned_index = self.start_tcp6_write_frame(packet_index, candidate);
                self.frames
                    .push(LinuxVnetPreparedWriteFrame::Vectored(owned_index));
                self.open_tcp6_flows.push((flow, owned_index));
                continue;
            }

            self.open_tcp6_flows.clear();
            self.frames
                .push(LinuxVnetPreparedWriteFrame::RawPacket(packet_index));
        }

        for frame in &mut self.vectored_frames[..self.vectored_frame_count] {
            linux_vnet_finish_write_frame(frame, &self.packet_refs);
        }
    }

    fn start_tcp6_write_frame(
        &mut self,
        packet_index: usize,
        candidate: LinuxVnetTcp6GroCandidate,
    ) -> usize {
        let index = self.vectored_frame_count;
        self.vectored_frame_count += 1;
        if index == self.vectored_frames.len() {
            self.vectored_frames.push(LinuxVnetWriteFrame {
                virtio_header: [0; LINUX_VIRTIO_NET_HDR_LEN],
                first_header: Vec::new(),
                first_packet_index: 0,
                first_payload_offset: 0,
                payload_segments: Vec::new(),
                tcp6_gro: None,
            });
        }
        linux_vnet_start_tcp6_write_frame_with_candidate(
            &mut self.vectored_frames[index],
            packet_index,
            candidate,
        );
        index
    }

    fn write_vectored_frame_to_tun(
        &mut self,
        file: &mut File,
        frame_index: usize,
    ) -> io::Result<()> {
        raw_write_linux_vnet_vectored_frame_to_tun(
            file.as_raw_fd(),
            &self.packet_refs,
            &self.vectored_frames[frame_index],
            &mut self.write_iov,
        )
    }
}

pub(super) fn write_packet_slices_to_tun<'a>(
    file: &mut File,
    packets: impl IntoIterator<Item = &'a [u8]>,
    preparer: &mut LinuxVnetWritePreparer,
) -> io::Result<()> {
    preparer.prepare(packets);

    let frame_count = preparer.frames.len();
    for frame_index in 0..frame_count {
        match preparer.frames[frame_index] {
            LinuxVnetPreparedWriteFrame::RawPacket(packet_index) => {
                preparer.packet_refs[packet_index].with_slice(|packet| {
                    raw_write_linux_vnet_packet_to_tun(file.as_raw_fd(), packet)
                })?;
            }
            LinuxVnetPreparedWriteFrame::Vectored(frame_index) => {
                preparer.write_vectored_frame_to_tun(file, frame_index)?;
            }
        }
    }

    Ok(())
}

fn linux_vnet_start_tcp6_write_frame_with_candidate(
    frame: &mut LinuxVnetWriteFrame,
    packet_index: usize,
    candidate: LinuxVnetTcp6GroCandidate,
) {
    frame.virtio_header = [0; LINUX_VIRTIO_NET_HDR_LEN];
    frame.first_header.clear();
    frame.first_packet_index = packet_index;
    frame.first_payload_offset = 0;
    frame.payload_segments.clear();
    frame.tcp6_gro = Some(LinuxVnetTcp6GroState {
        tcp_header_len: candidate.tcp_header_len,
        gso_size: candidate.payload_len,
        payload_len: candidate.payload_len,
        next_seq: candidate.seq.wrapping_add(candidate.payload_len as u32),
        psh_set: candidate.psh_set,
        flow: candidate.flow,
    });
}

fn linux_vnet_try_tcp6_gro_append_with_candidate(
    frame: &mut LinuxVnetWriteFrame,
    packet_index: usize,
    candidate: &LinuxVnetTcp6GroCandidate,
) -> bool {
    let Some(state) = frame.tcp6_gro.as_mut() else {
        return false;
    };
    if state.psh_set || state.payload_len % state.gso_size != 0 {
        return false;
    }
    if candidate.flow != state.flow
        || candidate.tcp_header_len != state.tcp_header_len
        || candidate.seq != state.next_seq
        || candidate.payload_len > state.gso_size
    {
        return false;
    }

    let header_len = 40 + candidate.tcp_header_len;
    let coalesced_packet_len =
        40 + state.tcp_header_len + state.payload_len + candidate.payload_len;
    if coalesced_packet_len > u16::MAX as usize {
        return false;
    }

    frame.payload_segments.push(LinuxVnetPayloadSegment {
        packet_index,
        payload_offset: header_len,
    });
    state.payload_len += candidate.payload_len;
    state.next_seq = state.next_seq.wrapping_add(candidate.payload_len as u32);
    if candidate.psh_set {
        state.psh_set = true;
    }
    true
}

fn linux_vnet_finish_write_frame(
    frame: &mut LinuxVnetWriteFrame,
    packet_refs: &[LinuxVnetPacketRef],
) {
    if let Some(state) = frame.tcp6_gro.take() {
        linux_vnet_finish_tcp6_write_frame(frame, packet_refs, state);
    }
}

fn linux_vnet_finish_tcp6_write_frame(
    frame: &mut LinuxVnetWriteFrame,
    packet_refs: &[LinuxVnetPacketRef],
    state: LinuxVnetTcp6GroState,
) {
    if state.payload_len <= state.gso_size {
        return;
    }

    let packet_len = 40usize
        .saturating_add(state.tcp_header_len)
        .saturating_add(state.payload_len);
    let transport_len = packet_len - 40;
    let header_len = 40 + state.tcp_header_len;
    frame.first_header.clear();
    packet_refs[frame.first_packet_index].with_slice(|first_packet| {
        frame
            .first_header
            .extend_from_slice(&first_packet[..header_len]);
    });
    frame.first_payload_offset = header_len;
    let packet = &mut frame.first_header;

    packet[4..6].copy_from_slice(&(transport_len as u16).to_be_bytes());
    if state.psh_set {
        packet[40 + LINUX_TCP_FLAGS_OFFSET] |= LINUX_TCP_FLAG_PSH;
    }

    let pseudo = linux_vnet_pseudo_header_sum(
        LINUX_IPPROTO_TCP,
        &packet[8..24],
        &packet[24..40],
        transport_len as u16,
    );
    let partial = !linux_vnet_checksum(&[], pseudo);
    packet[56..58].copy_from_slice(&partial.to_be_bytes());

    LinuxVirtioNetHdr {
        flags: LINUX_VIRTIO_NET_HDR_F_NEEDS_CSUM,
        gso_type: LINUX_VIRTIO_NET_HDR_GSO_TCPV6,
        hdr_len: header_len as u16,
        gso_size: state.gso_size as u16,
        csum_start: 40,
        csum_offset: 16,
    }
    .encode(&mut frame.virtio_header);
}

fn linux_vnet_tcp6_gro_candidate(packet: &[u8]) -> Option<LinuxVnetTcp6GroCandidate> {
    if packet.len() < 60 || packet[0] >> 4 != 6 || packet[6] != LINUX_IPPROTO_TCP {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_len != packet.len().checked_sub(40)? || payload_len < 20 {
        return None;
    }

    let tcp_header_len = usize::from(packet[52] >> 4) * 4;
    if !(20..=60).contains(&tcp_header_len) || packet.len() < 40 + tcp_header_len {
        return None;
    }
    let flags = packet[40 + LINUX_TCP_FLAGS_OFFSET];
    let psh_set = match flags {
        LINUX_TCP_FLAG_ACK => false,
        flags if flags == (LINUX_TCP_FLAG_ACK | LINUX_TCP_FLAG_PSH) => true,
        _ => return None,
    };

    let data_len = packet.len() - 40 - tcp_header_len;
    if data_len == 0 || data_len > u16::MAX as usize {
        return None;
    }

    let mut version_tc_flow = [0u8; 4];
    version_tc_flow.copy_from_slice(&packet[0..4]);
    let mut src_addr = [0u8; 16];
    src_addr.copy_from_slice(&packet[8..24]);
    let mut dst_addr = [0u8; 16];
    dst_addr.copy_from_slice(&packet[24..40]);
    let tcp = &packet[40..];
    let tcp_options_len =
        u8::try_from(tcp_header_len - 20).expect("TCP options length is at most 40 bytes");
    let mut tcp_options = [0u8; 40];
    tcp_options[..usize::from(tcp_options_len)].copy_from_slice(&tcp[20..tcp_header_len]);

    Some(LinuxVnetTcp6GroCandidate {
        tcp_header_len,
        payload_len: data_len,
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        psh_set,
        flow: LinuxVnetTcp6GroFlow {
            version_tc_flow,
            next_header: packet[6],
            hop_limit: packet[7],
            src_addr,
            dst_addr,
            src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
            dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
            ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
            tcp_options_len,
            tcp_options,
        },
    })
}

fn raw_write_linux_vnet_packet_to_tun(fd: RawFd, packet: &[u8]) -> io::Result<()> {
    let header = [0u8; LINUX_VIRTIO_NET_HDR_LEN];
    let frame_len = header.len() + packet.len();
    let iov = [
        libc::iovec {
            iov_base: header.as_ptr() as *mut libc::c_void,
            iov_len: header.len(),
        },
        libc::iovec {
            iov_base: packet.as_ptr() as *mut libc::c_void,
            iov_len: packet.len(),
        },
    ];
    let written = unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) };
    raw_tun_write_result(written, frame_len)?;
    crate::perf_profile::record_tun_write_frame(frame_len);
    Ok(())
}

fn raw_write_linux_vnet_vectored_frame_to_tun(
    fd: RawFd,
    packet_refs: &[LinuxVnetPacketRef],
    frame: &LinuxVnetWriteFrame,
    iov: &mut Vec<libc::iovec>,
) -> io::Result<()> {
    let first_ref = packet_refs[frame.first_packet_index];
    let first_header = frame.first_header.as_slice();
    let first_payload_len = first_ref.len_from_offset(frame.first_payload_offset);
    let iov_count = frame
        .payload_segments
        .len()
        .saturating_add(2)
        .saturating_add(usize::from(!first_header.is_empty()));
    if iov_count > LINUX_IOV_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Linux vnet writev iovec count exceeds IOV_MAX",
        ));
    }

    let mut expected = LINUX_VIRTIO_NET_HDR_LEN
        .saturating_add(first_header.len())
        .saturating_add(first_payload_len);
    iov.clear();
    if iov.capacity() < iov_count {
        iov.reserve(iov_count - iov.capacity());
    }
    iov.push(libc::iovec {
        iov_base: frame.virtio_header.as_ptr() as *mut libc::c_void,
        iov_len: frame.virtio_header.len(),
    });
    if !first_header.is_empty() {
        iov.push(libc::iovec {
            iov_base: first_header.as_ptr() as *mut libc::c_void,
            iov_len: first_header.len(),
        });
    }
    iov.push(first_ref.iovec_from_offset(frame.first_payload_offset));
    for segment in &frame.payload_segments {
        let packet_ref = packet_refs[segment.packet_index];
        expected = expected.saturating_add(packet_ref.len_from_offset(segment.payload_offset));
        iov.push(packet_ref.iovec_from_offset(segment.payload_offset));
    }
    let written = unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) };
    let result = raw_tun_write_result(written, expected);
    if result.is_ok() {
        crate::perf_profile::record_tun_write_frame(expected);
    }
    iov.clear();
    result
}

fn raw_tun_write_result(written: libc::ssize_t, expected: usize) -> io::Result<()> {
    if written < 0 {
        Err(io::Error::last_os_error())
    } else if written as usize != expected {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short Linux vnet TUN write: {} of {}", written, expected),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
include!("linux_vnet_tests.rs");
