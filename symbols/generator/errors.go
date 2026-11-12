package generator

import "errors"

var (
	ErrNoBTF        = errors.New("generator: no btf")
	ErrPointerSize  = errors.New("generator: pointer size is not 4 or 8")
	ErrTooManyTypes = errors.New("generator: btf holds more types than MaxTableEntries")
	ErrBanner       = errors.New("generator: banner is empty, not utf-8, or holds a nul before its last byte")
	ErrAddressRule  = errors.New("generator: unknown kallsyms address rule")
	ErrBannerSymbol = errors.New("generator: kallsyms gives linux_banner no single address")
)

// A refusal names why one member, type or name was left out of the table;
// the report counts refusals by this text.
type refusal string

func (r refusal) Error() string { return string(r) }

const (
	refuseUnresolvable    refusal = "type reference loops or nests past MaxRecursionDepth"
	refuseOperators       refusal = "type nests more pointers and arrays than a table expression holds"
	refuseUnnamedScalar   refusal = "integer or float has no usable name"
	refuseKind            refusal = "type reference reaches a kind no member can have"
	refuseFunction        refusal = "function type not reached through a pointer"
	refuseForwardName     refusal = "forward declaration has no identifier name"
	refuseMemberName      refusal = "member name is not an identifier"
	refuseDuplicateMember refusal = "member name repeats in its record"
	refuseUnionOffset     refusal = "union member not at offset 0"
	refuseOffsetOrder     refusal = "member offset below the previous member's"
	refuseOffsetPast      refusal = "member offset past the record's size"
	refuseByteOffset      refusal = "member that is not a bitfield starts inside a byte"
	refuseBitfieldBase    refusal = "bitfield on a type other than an integer or enumeration"
	refuseBitfieldRegular refusal = "bitfield with kind_flag on an integer that is not regular"
	refuseBitfieldFit     refusal = "bitfield does not fit a storage unit of its type"
	refuseUnnamedEmbed    refusal = "unnamed member of a derived type"
	refuseRefusedType     refusal = "member type was refused"
	refuseTypeName        refusal = "structure, union or enumeration name is not an identifier"
	refuseEnumWidth       refusal = "enumeration size is not 1, 2, 4 or 8"
	refuseConstantName    refusal = "enumeration constant name is not an identifier"
	refuseConstantRepeat  refusal = "enumeration constant name repeats"
	refuseScalarConflict  refusal = "integer or float definitions of one name disagree"
	refuseTypedefName     refusal = "typedef name is not an identifier"
	refuseTypedefDerived  refusal = "typedef names a pointer, array, function or void"
	refuseTypedefForward  refusal = "typedef names a type that is only declared"
	refuseTypedefTaken    refusal = "typedef name is already a type of its kind"
	refuseTypedefConflict refusal = "typedefs of one name name different types"
)
