package symbols_test

import (
	"fmt"

	"github.com/aoiflux/libvapour/symbols"
)

const listTable = `{
  "vsym": 1,
  "pointer_width": 8,
  "scalars": [
    {"name": "unsigned long long", "width": 8, "kind": "integer"}
  ],
  "records": [
    {"name": "_ENTRY", "width": 24, "members": [
      {"name": "Next", "offset": 0, "type": "*_ENTRY"},
      {"name": "Flags", "offset": 8, "type": "@4:2 unsigned long long"},
      {"name": "Count", "offset": 16, "type": "unsigned long long"}
    ]}
  ],
  "addresses": [
    {"name": "EntryHead", "address": "0x2000"}
  ]
}
`

func ExampleDecode() {
	table, err := symbols.Decode("example", []byte(listTable))
	if err != nil {
		fmt.Println(err)
		return
	}
	count, err := table.Field("_ENTRY", "Count")
	if err != nil {
		fmt.Println(err)
		return
	}
	flags, err := symbols.ResolveIntField(table, "_ENTRY", "Flags")
	if err != nil {
		fmt.Println(err)
		return
	}
	head, err := table.LookupSymbol("EntryHead")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Count is at +%d; Flags is %d bits from bit %d of an %d-byte unit\n",
		count.Offset, flags.BitLength, flags.BitOffset, flags.Width)
	fmt.Printf("EntryHead is at 0x%x\n", head.Address)
	if _, err := table.Field("_ENTRY", "Prev"); err != nil {
		fmt.Println(err)
	}
	// Output:
	// Count is at +16; Flags is 2 bits from bit 4 of an 8-byte unit
	// EntryHead is at 0x2000
	// symbols: type "_ENTRY" has no field "Prev"
}
