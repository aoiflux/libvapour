package linuxobj

import "fmt"

var interfaceFlagNames = [...]string{
	"IFF_UP", "IFF_BROADCAST", "IFF_DEBUG", "IFF_LOOPBACK", "IFF_POINTOPOINT", "IFF_NOTRAILERS", "IFF_RUNNING",
	"IFF_NOARP", "IFF_PROMISC", "IFF_ALLMULTI", "IFF_MASTER", "IFF_SLAVE", "IFF_MULTICAST", "IFF_PORTSEL",
	"IFF_AUTOMEDIA", "IFF_DYNAMIC", "IFF_LOWER_UP", "IFF_DORMANT", "IFF_ECHO",
}

const (
	iffPromisc  = 1 << 8
	iffAllMulti = 1 << 9
	iffRunning  = 1 << 6
	iffLowerUp  = 1 << 16
	iffDormant  = 1 << 17
)

var operStateNames = [...]string{
	"IF_OPER_UNKNOWN", "IF_OPER_NOTPRESENT", "IF_OPER_DOWN", "IF_OPER_LOWERLAYERDOWN", "IF_OPER_TESTING",
	"IF_OPER_DORMANT", "IF_OPER_UP",
}

const (
	operUnknown = 0
	operUp      = 6
)

const (
	linkStateStart     = 0
	linkStateNoCarrier = 2
	linkStateDormant   = 4
)

const (
	rtScopeUniverse = 0
	rtScopeSite     = 200
	rtScopeLink     = 253
	rtScopeHost     = 254
	rtScopeNowhere  = 255
)

const (
	IFAHost = 0x10
	IFALink = 0x20
	IFASite = 0x40
)

const maxHardwareAddress = 32

func InterfaceFlagNames(flags uint64) []string {
	var out []string
	for bit := uint64(0); bit < 64; bit++ {
		if flags&(1<<bit) == 0 {
			continue
		}
		if bit < uint64(len(interfaceFlagNames)) {
			out = append(out, interfaceFlagNames[bit])
		} else {
			out = append(out, fmt.Sprintf("%#x", uint64(1)<<bit))
		}
	}
	return out
}

func OperStateName(v uint64) (string, bool) {
	if v < uint64(len(operStateNames)) {
		return operStateNames[v], true
	}
	return "", false
}

func RouteScopeName(scope uint64) string {
	switch scope {
	case rtScopeUniverse:
		return "universe"
	case rtScopeSite:
		return "site"
	case rtScopeLink:
		return "link"
	case rtScopeHost:
		return "host"
	case rtScopeNowhere:
		return "nowhere"
	}
	return fmt.Sprintf("scope=%d", scope)
}

func IPv6RouteScope(ifaScope uint64) uint64 {
	switch {
	case ifaScope&IFAHost != 0:
		return rtScopeHost
	case ifaScope&IFALink != 0:
		return rtScopeLink
	case ifaScope&IFASite != 0:
		return rtScopeSite
	}
	return rtScopeUniverse
}
