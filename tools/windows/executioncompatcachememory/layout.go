package executioncompatcachememory

// ahcache.sys publishes no types for these objects; the offsets were read from
// its code on builds 14393, 19045 and 26100 (S41 3.3 and 3.5).
const (
	handleSymbol = "AhcCacheHandle"
	driverName   = "ahcache.sys"

	cacheStoreOffset = 0x08
	storeListOffset  = 0x68

	elementKeyOffset  = 0x18
	elementDataOffset = 0x28
	elementSize       = 0x30

	dataTimeOffset   = 0x08
	dataSizeOffset   = 0x10
	dataBufferOffset = 0x18
	dataObjectSize   = 0x20
)
