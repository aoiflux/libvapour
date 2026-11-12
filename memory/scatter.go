package memory

type ScatterRequest struct {
	Offset uint64
	Size   uint64
	Tag    string
}

type ScatterResult struct {
	Request ScatterRequest
	Data    []byte
	Error   string
}

// One failed request leaves the others untouched; results keep the order
// of the requests.
func ScatterRead(reader MemoryReader, requests []ScatterRequest) []ScatterResult {
	out := make([]ScatterResult, len(requests))
	for i, req := range requests {
		out[i].Request = req
		if reader == nil {
			out[i].Error = "memory: no reader"
			continue
		}
		b, err := reader.ReadAt(req.Offset, req.Size)
		if err != nil {
			out[i].Error = err.Error()
			continue
		}
		out[i].Data = b
	}
	return out
}
