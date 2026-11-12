package gui

// Measured on the captures (S57 M1 to M9) and, where a routine touches the
// member, confirmed by disassembly of the captured win32kfull.sys (S57 D1 to
// D5). Member names are the specification's own (owner question Q3).
var measured = []Layout{
	{
		Name:               "14393",
		Build:              14393,
		GUID:               "7F11BE3D0349423498439C1B125B8D98",
		Age:                1,
		Station:            StationMembers{SessionID: 0x0, Next: 0x8, Desktops: 0x10},
		Desktop:            DesktopMembers{Info: 0x8, Next: 0x10, Station: 0x18, Threads: 0xa0, HeapBase: 0x78, HeapSize: 0x80},
		DesktopInfoWindow:  0x10,
		Thread:             ThreadMembers{EThread: 0x0, ProcessInfo: 0x170, Desktop: 0x190, Link: 0x288},
		ProcessInfoProcess: 0x0,
		Window: WindowMembers{
			Thread: 0x10, Desktop: 0x18, Self: 0x20,
			Next: 0x48, Parent: 0x58, Child: 0x60,
			TextLength: InWindow, TextLengthAt: 0xd8, TextMaximum: InWindow, TextMaximumAt: 0xdc, TextBuffer: 0xe0,
			ProcedureIn: InWindow, Procedure: 0x90,
		},
	},
	{
		Name:               "19045",
		Build:              19045,
		GUID:               "A8A69A7FD22B0D044A322341F88A665F",
		Age:                1,
		Station:            StationMembers{SessionID: 0x0, Next: 0x8, Desktops: 0x10},
		Desktop:            DesktopMembers{Info: 0x8, Next: 0x20, Station: 0x28, Threads: 0xa8, HeapBase: 0x80, HeapSize: 0x88},
		DesktopInfoWindow:  0x18,
		Thread:             ThreadMembers{EThread: 0x0, ProcessInfo: 0x1a8, Desktop: 0x1c8, Link: 0x2e8},
		ProcessInfoProcess: 0x0,
		Window:             shadowedWindow,
	},
	{
		Name:               "26100 server",
		Build:              26100,
		GUID:               "9E28166718391720C46B2FAA29743066",
		Age:                1,
		Station:            StationMembers{SessionID: 0x0, Next: 0x8, Desktops: 0x10},
		Desktop:            DesktopMembers{Info: 0x8, Next: 0x20, Station: 0x28, Threads: 0xa0, HeapBase: 0x78, HeapSize: 0x80},
		DesktopInfoWindow:  0x18,
		Thread:             ThreadMembers{EThread: 0x0, ProcessInfo: 0x1d0, Desktop: 0x1f0, Link: 0x308},
		ProcessInfoProcess: 0x0,
		Window:             shadowedWindow,
	},
	{
		Name:               "26100 client",
		Build:              26100,
		GUID:               "9424C46D16DB7704265494D882A35C6E",
		Age:                1,
		Station:            StationMembers{SessionID: 0x0, Next: 0x8, Desktops: 0x10},
		Desktop:            DesktopMembers{Info: 0x8, Next: 0x20, Station: 0x28, Threads: 0xb0, HeapBase: 0x88, HeapSize: 0x90},
		DesktopInfoWindow:  0x18,
		Thread:             ThreadMembers{EThread: 0x0, ProcessInfo: 0x1d0, Desktop: 0x1f0, Link: 0x308},
		ProcessInfoProcess: 0x0,
		Window:             shadowedWindow,
	},
}

var shadowedWindow = WindowMembers{
	Thread: 0x10, Desktop: 0x18, Self: 0x20,
	Next: 0x58, Parent: 0x68, Child: 0x70,
	HasShadow: true, Shadow: 0x28, ShadowOffset: 0x30,
	TextLength: InShadow, TextLengthAt: 0xb8, TextMaximum: InShadow, TextMaximumAt: 0xbc, TextBuffer: 0xb8,
	ProcedureIn: InShadow, Procedure: 0x78,
}
