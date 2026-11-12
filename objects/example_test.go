package objects_test

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/aoiflux/libvapour/objects"
	"github.com/aoiflux/libvapour/symbols"
)

type flat []byte

func (f flat) ReadAt(offset, size uint64) ([]byte, error) {
	if offset > uint64(len(f)) || size > uint64(len(f))-offset {
		return nil, fmt.Errorf("0x%x bytes at 0x%x: past the end", size, offset)
	}
	return f[offset : offset+size], nil
}

func (f flat) Size() uint64 { return uint64(len(f)) }

const taskTable = `{
  "vsym": 1,
  "pointer_width": 8,
  "scalars": [
    {"name": "int", "width": 4, "kind": "integer", "signed": true},
    {"name": "char", "width": 1, "kind": "char"}
  ],
  "records": [
    {"name": "task", "width": 32, "members": [
      {"name": "pid", "offset": 0, "type": "int"},
      {"name": "parent", "offset": 8, "type": "*task"},
      {"name": "comm", "offset": 16, "type": "[16]char"}
    ]}
  ]
}
`

func ExampleObject_Pointer() {
	table, err := symbols.Decode("example", []byte(taskTable))
	if err != nil {
		fmt.Println(err)
		return
	}
	mem := make(flat, 0x100)
	binary.LittleEndian.PutUint32(mem[0x80:], 1)
	copy(mem[0x90:], "init")
	binary.LittleEndian.PutUint32(mem[0x40:], 812)
	binary.LittleEndian.PutUint64(mem[0x48:], 0x80)
	copy(mem[0x50:], "sshd")

	for task := objects.New(mem, table, "task", 0x40); ; {
		pid, err := task.Uint32("pid")
		if err != nil {
			fmt.Println(err)
			return
		}
		comm, err := task.Bytes("comm", 4)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("%s pid %d\n", comm, pid)
		task, err = task.Pointer("parent")
		if errors.Is(err, objects.ErrNullPointer) {
			break
		}
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	// Output:
	// sshd pid 812
	// init pid 1
}
