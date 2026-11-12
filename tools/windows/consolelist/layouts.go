package consolelist

// Keyed by the file-set build (winkernel.FileSetBuild). Only the mem2
// conhost.exe (19045, PDB F020B0E2) was measured; 14393 keeps its console
// in another module and the 26100 hosts hold no history and no readable
// debug record, so both are refused (S67 M14, M15).
var layoutForBuild = map[uint64]*Layout{
	19041: measured19041(),
}

func measured19041() *Layout {
	l := &Layout{Name: "conhost-19041"}

	// The list node's links, then the element (s_Find: next at 0, element
	// at 0x10).
	l.node.next = 0
	l.node.size = 0x10

	// A string keeps its UTF-16 units in itself until its capacity reaches
	// 8 (IsAppNameMatch: length 0x10, capacity 0x18, cmp capacity, 8).
	l.text.chars = 0
	l.text.pointer = 0
	l.text.length = prim{off: 0x10, size: 8}
	l.text.capacity = prim{off: 0x18, size: 8}
	l.text.size = 0x20

	l.vector.begin = 0
	l.vector.end = 8
	l.vector.capacityEnd = 0x10

	l.history.commands = 0x10
	l.history.capacity = prim{off: 0x28, size: 8}
	l.history.application = 0x30
	l.history.process = 0x50
	l.history.lastDisplayed = prim{off: 0x5c, size: 2, signed: true}
	l.history.size = 0x60

	l.process.pid = prim{off: 0x1c, size: 4}

	c := &consoleLayout{}
	c.screenWidth = prim{off: 0x20, size: 2, signed: true}
	c.screenHeight = prim{off: 0x22, size: 2, signed: true}
	c.historySize = prim{off: 0x90, size: 4}
	c.historyMax = prim{off: 0x94, size: 4}
	c.processList = 0x558
	c.processCount = prim{off: 0x560, size: 8}
	c.screenList = 0x570
	c.title = 0x698
	c.originalTitle = 0x6d8
	c.activeScreen = 0x718
	// The alias map's own list starts one pointer into the map (S67 M13).
	c.aliases = 0x2310
	c.historyList = 0x2368
	c.historyCount = prim{off: 0x2370, size: 8}

	c.processNode.process = 0x10
	c.aliasEntry.name = 0x10
	c.aliasEntry.aliases = 0x38
	c.alias.source = 0x10
	c.alias.target = 0x30
	c.screen.textBuffer = 0x38
	c.screen.next = 0x40
	c.textBuffer.rows = 8
	c.textBuffer.rowCount = prim{off: 0x20, size: 8}
	c.textBuffer.firstRow = prim{off: 0x58, size: 2, signed: true}
	c.row.cells = 8
	c.row.width = prim{off: 0x50, size: 8}
	l.console = c
	return l
}
