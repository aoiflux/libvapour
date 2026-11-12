package consolelist

// conhost.exe has public symbols and no types, so every offset here was
// measured on a capture and tied to the instructions that read it (S67).
// Offsets of a history are from its list node: the library's list keeps the
// element after the node's two links.
type Layout struct {
	Name string

	node struct {
		next int64
		size uint64
	}
	history struct {
		commands      int64
		application   int64
		process       int64
		capacity      prim
		lastDisplayed prim
		size          uint64
	}
	process struct {
		pid prim
	}
	text struct {
		chars, pointer   int64
		length, capacity prim
		size             uint64
	}
	vector struct{ begin, end, capacityEnd int64 }

	console   *consoleLayout
	noConsole string
}

type consoleLayout struct {
	screenWidth, screenHeight             prim
	historySize, historyMax, historyCount prim
	processCount                          prim
	title, originalTitle                  int64
	processList, historyList, aliases     int64
	activeScreen, screenList              int64

	processNode struct{ process int64 }
	aliasEntry  struct{ name, aliases int64 }
	alias       struct{ source, target int64 }

	screen     struct{ textBuffer, next int64 }
	textBuffer struct {
		rows               int64
		rowCount, firstRow prim
	}
	row struct {
		cells int64
		width prim
	}
}

type prim struct {
	off    int64
	size   uint64
	signed bool
}
