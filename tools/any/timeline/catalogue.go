package timeline

import (
	"time"

	"github.com/aoiflux/libvapour/tools/any/processlist"
	"github.com/aoiflux/libvapour/tools/any/processscan"
	"github.com/aoiflux/libvapour/tools/linux/boottime"
	"github.com/aoiflux/libvapour/tools/linux/fileopen"
	"github.com/aoiflux/libvapour/tools/linux/pagecache"
	"github.com/aoiflux/libvapour/tools/linux/shellhistory"
	"github.com/aoiflux/libvapour/tools/windows/executionamcache"
	"github.com/aoiflux/libvapour/tools/windows/executioncompatcachememory"
	"github.com/aoiflux/libvapour/tools/windows/executionuserassist"
	"github.com/aoiflux/libvapour/tools/windows/librarylist"
	"github.com/aoiflux/libvapour/tools/windows/moduleunloaded"
	"github.com/aoiflux/libvapour/tools/windows/network"
	"github.com/aoiflux/libvapour/tools/windows/ntfsrecord"
	"github.com/aoiflux/libvapour/tools/windows/objectlinks"
	"github.com/aoiflux/libvapour/tools/windows/sessionlist"
	"github.com/aoiflux/libvapour/tools/windows/tasklist"
	"github.com/aoiflux/libvapour/tools/windows/threadlist"
	"github.com/aoiflux/libvapour/tools/windows/threadorphaned"
	"github.com/aoiflux/libvapour/tools/windows/threadscan"
)

type timeOK struct {
	t  time.Time
	ok bool
}

// Run order: lists before scans of the same objects, then registry and
// file sources; the order only decides which source a shared cache is
// filled by, not the output order.
var catalogue = []source{
	{tool: processlist.Name, os: windows, read: rowsOf(listedProcess)},
	{tool: processscan.Name, os: windows, read: rowsOf(scannedProcess)},
	{tool: threadlist.Name, os: windows, read: rowsOf(listedThread)},
	{tool: threadscan.Name, os: windows, read: rowsOf(scannedThread)},
	{tool: threadorphaned.Name, os: windows, read: rowsOf(scannedThread)},
	{tool: librarylist.Name, os: windows, read: rowsOf(library)},
	{tool: sessionlist.Name, os: windows, read: rowsOf(session)},
	{tool: network.NetworkListName, os: windows, read: rowsOf(endpoint)},
	{tool: network.Name, os: windows, read: rowsOf(endpoint)},
	{tool: objectlinks.Name, os: windows, read: rowsOf(symlink)},
	{tool: moduleunloaded.Name, os: windows, read: rowsOf(unloadedModule)},
	{tool: tasklist.Name, os: windows, read: rowsOf(task)},
	{tool: executioncompatcachememory.Name, os: windows, read: rowsOf(compatEntry)},
	{tool: executionuserassist.Name, os: windows, read: readUserAssist},
	{tool: executionamcache.Name, os: windows, read: rowsOf(amcacheEntry)},
	{tool: ntfsrecord.Name, os: windows, read: rowsOf(ntfsAttribute)},

	{tool: processlist.Name, os: linux, read: rowsOf(linuxTask), overrides: map[string]any{processlist.OptionThreads: true}},
	{tool: boottime.Name, os: linux, read: rowsOf(bootRow)},
	{tool: shellhistory.Name, os: linux, read: rowsOf(historyEntry)},
	{tool: fileopen.Name, os: linux, read: rowsOf(openFile)},
	{tool: pagecache.FilesName, os: linux, read: rowsOf(cachedInode)},
}
