package tasklist

import "fmt"

type ActionKind string

const (
	ActionExec       ActionKind = "Exec"
	ActionComHandler ActionKind = "ComHandler"
)

type Action struct {
	Kind             ActionKind
	Record           uint16
	ID               string
	Command          string
	Arguments        string
	WorkingDirectory string
	ClassID          string
	Data             string
}

type ActionSet struct {
	Context string
	Actions []Action
}

// S37 M10: format 2 on build 14393, 3 on the later builds; 3 adds two bytes
// after each Exec record.
const (
	actionFormatEarly = 2
	actionFormatLate  = 3
)

const (
	recordExec       = 0x6666
	recordComHandler = 0x7777
)

const classIDBytes = 16

// Unlike the Triggers value, the Actions value is not slotted: every field
// follows the one before it.
func runText(c *cursor) (string, error) {
	n, err := c.u32()
	if err != nil {
		return "", err
	}
	b, err := c.take(uint64(n))
	if err != nil {
		return "", err
	}
	return text(b)
}

func DecodeActions(b []byte, maxRecords int) (ActionSet, error) {
	var set ActionSet
	c := &cursor{b: b}
	format, err := c.u16()
	if err != nil {
		return set, err
	}
	if format != actionFormatEarly && format != actionFormatLate {
		return set, fmt.Errorf("%w: Actions format %d", ErrFormat, format)
	}
	if set.Context, err = runText(c); err != nil {
		return set, err
	}
	for c.left() > 0 {
		if len(set.Actions) >= maxRecords {
			err := fmt.Errorf("%w: more than %d records", ErrLimit, maxRecords)
			return set, &recordError{what: "action", at: c.at, err: err}
		}
		at := c.at
		a, err := decodeAction(c, format)
		if err != nil {
			return set, &recordError{what: "action", at: at, err: err}
		}
		set.Actions = append(set.Actions, a)
	}
	return set, nil
}

func decodeAction(c *cursor, format uint16) (Action, error) {
	var a Action
	tag, err := c.u16()
	if err != nil {
		return a, err
	}
	a.Record = tag
	switch tag {
	case recordExec:
		a.Kind = ActionExec
	case recordComHandler:
		a.Kind = ActionComHandler
	default:
		return a, fmt.Errorf("%w: 0x%04x", ErrRecordKind, tag)
	}
	if a.ID, err = runText(c); err != nil {
		return a, err
	}
	if a.Kind == ActionComHandler {
		id, err := c.take(classIDBytes)
		if err != nil {
			return a, err
		}
		a.ClassID = guidString(id)
		a.Data, err = runText(c)
		return a, err
	}
	for _, field := range []*string{&a.Command, &a.Arguments, &a.WorkingDirectory} {
		if *field, err = runText(c); err != nil {
			return a, err
		}
	}
	if format == actionFormatLate {
		_, err = c.take(2)
	}
	return a, err
}
