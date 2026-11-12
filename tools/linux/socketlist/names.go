package socketlist

import "strconv"

// S13 N1: AF_* by value; 45 (AF_MCTP) is at v6.1 onwards, not at v4.19.
var familyNames = [...]string{
	0: "AF_UNSPEC", 1: "AF_UNIX", 2: "AF_INET", 3: "AF_AX25", 4: "AF_IPX", 5: "AF_APPLETALK", 6: "AF_NETROM",
	7: "AF_BRIDGE", 8: "AF_ATMPVC", 9: "AF_X25", 10: "AF_INET6", 11: "AF_ROSE", 12: "AF_DECnet",
	13: "AF_NETBEUI", 14: "AF_SECURITY", 15: "AF_KEY", 16: "AF_NETLINK", 17: "AF_PACKET", 18: "AF_ASH",
	19: "AF_ECONET", 20: "AF_ATMSVC", 21: "AF_RDS", 22: "AF_SNA", 23: "AF_IRDA", 24: "AF_PPPOX",
	25: "AF_WANPIPE", 26: "AF_LLC", 27: "AF_IB", 28: "AF_MPLS", 29: "AF_CAN", 30: "AF_TIPC",
	31: "AF_BLUETOOTH", 32: "AF_IUCV", 33: "AF_RXRPC", 34: "AF_ISDN", 35: "AF_PHONET", 36: "AF_IEEE802154",
	37: "AF_CAIF", 38: "AF_ALG", 39: "AF_NFC", 40: "AF_VSOCK", 41: "AF_KCM", 42: "AF_QIPCRTR", 43: "AF_SMC",
	44: "AF_XDP", 45: "AF_MCTP",
}

const (
	afUnix      = 1
	afInet      = 2
	afInet6     = 10
	afNetlink   = 16
	afPacket    = 17
	afBluetooth = 31
	afVsock     = 40
	afXDP       = 44
)

// S13 N2.
var typeNames = map[uint64]string{
	1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW", 4: "SOCK_RDM", 5: "SOCK_SEQPACKET", 6: "SOCK_DCCP",
	10: "SOCK_PACKET",
}

// S13 N3: TCP_BOUND_INACTIVE (13) is at v6.14 and v6.17, not at v4.19 to v6.4.
var tcpStateNames = [...]string{
	1: "TCP_ESTABLISHED", 2: "TCP_SYN_SENT", 3: "TCP_SYN_RECV", 4: "TCP_FIN_WAIT1", 5: "TCP_FIN_WAIT2",
	6: "TCP_TIME_WAIT", 7: "TCP_CLOSE", 8: "TCP_CLOSE_WAIT", 9: "TCP_LAST_ACK", 10: "TCP_LISTEN",
	11: "TCP_CLOSING", 12: "TCP_NEW_SYN_RECV", 13: "TCP_BOUND_INACTIVE",
}

// S13 N4.
var ipProtocolNames = map[uint64]string{
	0: "IPPROTO_IP", 1: "IPPROTO_ICMP", 2: "IPPROTO_IGMP", 4: "IPPROTO_IPIP", 6: "IPPROTO_TCP", 8: "IPPROTO_EGP",
	12: "IPPROTO_PUP", 17: "IPPROTO_UDP", 22: "IPPROTO_IDP", 29: "IPPROTO_TP", 33: "IPPROTO_DCCP",
	41: "IPPROTO_IPV6", 46: "IPPROTO_RSVP", 47: "IPPROTO_GRE", 50: "IPPROTO_ESP", 51: "IPPROTO_AH",
	58: "IPPROTO_ICMPV6", 92: "IPPROTO_MTP", 94: "IPPROTO_BEETPH", 98: "IPPROTO_ENCAP", 103: "IPPROTO_PIM",
	108: "IPPROTO_COMP", 115: "IPPROTO_L2TP", 132: "IPPROTO_SCTP", 136: "IPPROTO_UDPLITE", 137: "IPPROTO_MPLS",
	143: "IPPROTO_ETHERNET", 144: "IPPROTO_AGGFRAG", 255: "IPPROTO_RAW", 256: "IPPROTO_SMC", 262: "IPPROTO_MPTCP",
}

// S13 N5.
var netlinkProtocolNames = map[uint64]string{
	0: "NETLINK_ROUTE", 1: "NETLINK_UNUSED", 2: "NETLINK_USERSOCK", 3: "NETLINK_FIREWALL", 4: "NETLINK_SOCK_DIAG",
	5: "NETLINK_NFLOG", 6: "NETLINK_XFRM", 7: "NETLINK_SELINUX", 8: "NETLINK_ISCSI", 9: "NETLINK_AUDIT",
	10: "NETLINK_FIB_LOOKUP", 11: "NETLINK_CONNECTOR", 12: "NETLINK_NETFILTER", 13: "NETLINK_IP6_FW",
	14: "NETLINK_DNRTMSG", 15: "NETLINK_KOBJECT_UEVENT", 16: "NETLINK_GENERIC", 18: "NETLINK_SCSITRANSPORT",
	19: "NETLINK_ECRYPTFS", 20: "NETLINK_RDMA", 21: "NETLINK_CRYPTO", 22: "NETLINK_SMC",
}

// S13 N6: netlink writes sk_state only in connect(); until then it keeps the
// TCP_CLOSE that sock_init_data gives every sock.
var netlinkStateNames = [...]string{0: "NETLINK_UNCONNECTED", 1: "NETLINK_CONNECTED", 7: "TCP_CLOSE"}

// S13 N7: a subset of if_ether.h; the rest print in hexadecimal.
var ethProtocolNames = map[uint64]string{
	0x0001: "ETH_P_802_3", 0x0003: "ETH_P_ALL", 0x0060: "ETH_P_LOOP", 0x0800: "ETH_P_IP", 0x0806: "ETH_P_ARP",
	0x8035: "ETH_P_RARP", 0x8100: "ETH_P_8021Q", 0x86dd: "ETH_P_IPV6", 0x8847: "ETH_P_MPLS_UC",
	0x8863: "ETH_P_PPP_DISC", 0x8864: "ETH_P_PPP_SES", 0x888e: "ETH_P_PAE", 0x88a8: "ETH_P_8021AD",
	0x88cc: "ETH_P_LLDP",
}

// S13 N8.
var btProtocolNames = [...]string{
	0: "BTPROTO_L2CAP", 1: "BTPROTO_HCI", 2: "BTPROTO_SCO", 3: "BTPROTO_RFCOMM", 4: "BTPROTO_BNEP",
	5: "BTPROTO_CMTP", 6: "BTPROTO_HIDP", 7: "BTPROTO_AVDTP", 8: "BTPROTO_ISO",
}

// S13 N9.
var btStateNames = [...]string{
	1: "BT_CONNECTED", 2: "BT_OPEN", 3: "BT_BOUND", 4: "BT_LISTEN", 5: "BT_CONNECT", 6: "BT_CONNECT2",
	7: "BT_CONFIG", 8: "BT_DISCONN", 9: "BT_CLOSED",
}

// S13 N10.
var xskStateNames = [...]string{0: "XSK_READY", 1: "XSK_BOUND", 2: "XSK_UNBOUND"}

func indexed(table []string, v uint64) (string, bool) {
	if v < uint64(len(table)) && table[v] != "" {
		return table[v], true
	}
	return "", false
}

func keyed(table map[uint64]string, v uint64) (string, bool) {
	s, ok := table[v]
	return s, ok
}

// A value with no name keeps its number, so the row still says what was read.
func orNumber(name string, ok bool, v uint64) string {
	if ok {
		return name
	}
	return strconv.FormatUint(v, 10)
}

func FamilyName(v uint64) string {
	s, ok := indexed(familyNames[:], v)
	if ok {
		return s
	}
	return "AF " + strconv.FormatUint(v, 10)
}

func TypeName(v uint64) string {
	s, ok := keyed(typeNames, v)
	if ok {
		return s
	}
	return "SOCK " + strconv.FormatUint(v, 10)
}
