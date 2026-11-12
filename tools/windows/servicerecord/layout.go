package servicerecord

// Offsets and tags are S34 M1 to M8: the services.pdb files carry publics
// only, so every member here is measured (S34 O1).
type layout struct {
	name         string
	build        uint32
	tag          uint32
	tagAt        uint64
	imagePointer bool

	previous, next  uint64
	serviceName     uint64
	displayName     uint64
	sequence        uint64
	status          uint64
	startType       uint64
	errorControl    uint64
	processOrDriver uint64
	imageProcessID  uint64

	head headForm
}

type headForm int

const (
	// A CServiceDatabase global: first and last record, a counter and a count.
	headDatabase headForm = iota
	// A _SERVICE_RECORD global whose next link is the first record.
	headSentinel
)

const (
	tagStruct   = 0x76724573 // "sErv"
	tagObject   = 0x39316353 // "Sc19"
	tagDatabase = 0x37326353 // "Sc27"
	tagSentinel = 0x37316353 // "Sc17"
	tagImage    = 0x36316353 // "Sc16"

	databaseFirst   = 0x08
	databaseLast    = 0x10
	databaseCounter = 0x20
	databaseCount   = 0x24

	imageCommandLine = 0x18

	recordAlignment = 16
	pointerSize     = 8
)

var layouts = []layout{
	{
		name: "14393", build: 14393, tag: tagStruct, tagAt: 0,
		previous: 0x08, next: 0x98, serviceName: 0x10, displayName: 0x18, sequence: 0x20,
		status: 0x40, startType: 0x5c, errorControl: 0x60, processOrDriver: 0x38, imageProcessID: 0x20,
		head: headSentinel,
	},
	{
		name: "19041", build: 19041, tag: tagObject, tagAt: 8, imagePointer: true,
		previous: 0x10, next: 0x18, serviceName: 0x38, displayName: 0x40, sequence: 0x20,
		status: 0x48, startType: 0x24, errorControl: 0x28, processOrDriver: 0x128, imageProcessID: 0x28,
		head: headDatabase,
	},
	{
		name: "26100", build: 26100, tag: tagObject, tagAt: 8, imagePointer: true,
		previous: 0x10, next: 0x18, serviceName: 0x38, displayName: 0x40, sequence: 0x20,
		status: 0x50, startType: 0x24, errorControl: 0x28, processOrDriver: 0x150, imageProcessID: 0x28,
		head: headDatabase,
	},
}

func (l layout) headTag() uint32 {
	if l.head == headSentinel {
		return tagSentinel
	}
	return tagDatabase
}

// The names are the PDB publics of S34 P1 and P2.
const (
	publicDatabase     = "?ServiceDatabase@@3VCServiceDatabase@@A"
	publicSentinel     = "?ServiceDatabase@@3U_SERVICE_RECORD@@A"
	publicSentinelSize = "?ScTotalNumServiceRecs@@3KA"
)

func layoutsWithTag(tag uint32) []layout {
	var out []layout
	for _, l := range layouts {
		if l.tag == tag {
			out = append(out, l)
		}
	}
	return out
}

func recordTags() []uint32 { return []uint32{tagStruct, tagObject} }
