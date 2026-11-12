package util_test

import (
	"fmt"

	"github.com/aoiflux/libvapour/util"
)

func ExampleFiletimeToTime() {
	for _, v := range []uint64{0, 116444736000000000, 133000000000000000} {
		if t, ok := util.FiletimeToTime(v); ok {
			fmt.Println(t.Format("2006-01-02T15:04:05Z"))
		} else {
			fmt.Println("no time")
		}
	}
	// Output:
	// no time
	// 1970-01-01T00:00:00Z
	// 2022-06-18T04:26:40Z
}

func ExampleDecodeUTF16LEZ() {
	fmt.Printf("%q\n", util.DecodeUTF16LEZ([]byte{'s', 0, 'm', 0, 's', 0, 0, 0, 'x', 0}))
	// Output:
	// "sms"
}
