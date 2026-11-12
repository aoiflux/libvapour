package driverscan

import "github.com/aoiflux/libvapour/util"

func unicodeLayout() util.UnicodeStringLayout {
	return util.UnicodeStringLayout{LengthOffset: 0, MaximumLengthOffset: 2, BufferOffset: 8, Size: 16}
}
