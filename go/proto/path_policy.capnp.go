// Code generated by capnpc-go. DO NOT EDIT.

package proto

import (
	capnp "zombiezen.com/go/capnproto2"
	text "zombiezen.com/go/capnproto2/encoding/text"
	schemas "zombiezen.com/go/capnproto2/schemas"
)

type Policy struct{ capnp.Struct }

// Policy_TypeID is the unique identifier for the type Policy.
const Policy_TypeID = 0x8562915c3c951576

func NewPolicy(s *capnp.Segment) (Policy, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 3})
	return Policy{st}, err
}

func NewRootPolicy(s *capnp.Segment) (Policy, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 3})
	return Policy{st}, err
}

func ReadRootPolicy(msg *capnp.Message) (Policy, error) {
	root, err := msg.RootPtr()
	return Policy{root.Struct()}, err
}

func (s Policy) String() string {
	str, _ := text.Marshal(0x8562915c3c951576, s.Struct)
	return str
}

func (s Policy) Acl() (ACL, error) {
	p, err := s.Struct.Ptr(0)
	return ACL{Struct: p.Struct()}, err
}

func (s Policy) HasAcl() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s Policy) SetAcl(v ACL) error {
	return s.Struct.SetPtr(0, v.Struct.ToPtr())
}

// NewAcl sets the acl field to a newly
// allocated ACL struct, preferring placement in s's segment.
func (s Policy) NewAcl() (ACL, error) {
	ss, err := NewACL(s.Struct.Segment())
	if err != nil {
		return ACL{}, err
	}
	err = s.Struct.SetPtr(0, ss.Struct.ToPtr())
	return ss, err
}

func (s Policy) Sequence() (string, error) {
	p, err := s.Struct.Ptr(1)
	return p.Text(), err
}

func (s Policy) HasSequence() bool {
	p, err := s.Struct.Ptr(1)
	return p.IsValid() || err != nil
}

func (s Policy) SequenceBytes() ([]byte, error) {
	p, err := s.Struct.Ptr(1)
	return p.TextBytes(), err
}

func (s Policy) SetSequence(v string) error {
	return s.Struct.SetText(1, v)
}

func (s Policy) Options() (Option_List, error) {
	p, err := s.Struct.Ptr(2)
	return Option_List{List: p.List()}, err
}

func (s Policy) HasOptions() bool {
	p, err := s.Struct.Ptr(2)
	return p.IsValid() || err != nil
}

func (s Policy) SetOptions(v Option_List) error {
	return s.Struct.SetPtr(2, v.List.ToPtr())
}

// NewOptions sets the options field to a newly
// allocated Option_List, preferring placement in s's segment.
func (s Policy) NewOptions(n int32) (Option_List, error) {
	l, err := NewOption_List(s.Struct.Segment(), n)
	if err != nil {
		return Option_List{}, err
	}
	err = s.Struct.SetPtr(2, l.List.ToPtr())
	return l, err
}

// Policy_List is a list of Policy.
type Policy_List struct{ capnp.List }

// NewPolicy creates a new list of Policy.
func NewPolicy_List(s *capnp.Segment, sz int32) (Policy_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 0, PointerCount: 3}, sz)
	return Policy_List{l}, err
}

func (s Policy_List) At(i int) Policy { return Policy{s.List.Struct(i)} }

func (s Policy_List) Set(i int, v Policy) error { return s.List.SetStruct(i, v.Struct) }

func (s Policy_List) String() string {
	str, _ := text.MarshalList(0x8562915c3c951576, s.List)
	return str
}

// Policy_Promise is a wrapper for a Policy promised by a client call.
type Policy_Promise struct{ *capnp.Pipeline }

func (p Policy_Promise) Struct() (Policy, error) {
	s, err := p.Pipeline.Struct()
	return Policy{s}, err
}

func (p Policy_Promise) Acl() ACL_Promise {
	return ACL_Promise{Pipeline: p.Pipeline.GetPipeline(0)}
}

type Option struct{ capnp.Struct }

// Option_TypeID is the unique identifier for the type Option.
const Option_TypeID = 0xff1928582247d7b2

func NewOption(s *capnp.Segment) (Option, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1})
	return Option{st}, err
}

func NewRootOption(s *capnp.Segment) (Option, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1})
	return Option{st}, err
}

func ReadRootOption(msg *capnp.Message) (Option, error) {
	root, err := msg.RootPtr()
	return Option{root.Struct()}, err
}

func (s Option) String() string {
	str, _ := text.Marshal(0xff1928582247d7b2, s.Struct)
	return str
}

func (s Option) Weight() int32 {
	return int32(s.Struct.Uint32(0))
}

func (s Option) SetWeight(v int32) {
	s.Struct.SetUint32(0, uint32(v))
}

func (s Option) Policy() (Policy, error) {
	p, err := s.Struct.Ptr(0)
	return Policy{Struct: p.Struct()}, err
}

func (s Option) HasPolicy() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s Option) SetPolicy(v Policy) error {
	return s.Struct.SetPtr(0, v.Struct.ToPtr())
}

// NewPolicy sets the policy field to a newly
// allocated Policy struct, preferring placement in s's segment.
func (s Option) NewPolicy() (Policy, error) {
	ss, err := NewPolicy(s.Struct.Segment())
	if err != nil {
		return Policy{}, err
	}
	err = s.Struct.SetPtr(0, ss.Struct.ToPtr())
	return ss, err
}

// Option_List is a list of Option.
type Option_List struct{ capnp.List }

// NewOption creates a new list of Option.
func NewOption_List(s *capnp.Segment, sz int32) (Option_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1}, sz)
	return Option_List{l}, err
}

func (s Option_List) At(i int) Option { return Option{s.List.Struct(i)} }

func (s Option_List) Set(i int, v Option) error { return s.List.SetStruct(i, v.Struct) }

func (s Option_List) String() string {
	str, _ := text.MarshalList(0xff1928582247d7b2, s.List)
	return str
}

// Option_Promise is a wrapper for a Option promised by a client call.
type Option_Promise struct{ *capnp.Pipeline }

func (p Option_Promise) Struct() (Option, error) {
	s, err := p.Pipeline.Struct()
	return Option{s}, err
}

func (p Option_Promise) Policy() Policy_Promise {
	return Policy_Promise{Pipeline: p.Pipeline.GetPipeline(0)}
}

type ACL struct{ capnp.Struct }

// ACL_TypeID is the unique identifier for the type ACL.
const ACL_TypeID = 0xcd0ebf47910e2043

func NewACL(s *capnp.Segment) (ACL, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 1})
	return ACL{st}, err
}

func NewRootACL(s *capnp.Segment) (ACL, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 1})
	return ACL{st}, err
}

func ReadRootACL(msg *capnp.Message) (ACL, error) {
	root, err := msg.RootPtr()
	return ACL{root.Struct()}, err
}

func (s ACL) String() string {
	str, _ := text.Marshal(0xcd0ebf47910e2043, s.Struct)
	return str
}

func (s ACL) Entries() (ACLEntry_List, error) {
	p, err := s.Struct.Ptr(0)
	return ACLEntry_List{List: p.List()}, err
}

func (s ACL) HasEntries() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s ACL) SetEntries(v ACLEntry_List) error {
	return s.Struct.SetPtr(0, v.List.ToPtr())
}

// NewEntries sets the entries field to a newly
// allocated ACLEntry_List, preferring placement in s's segment.
func (s ACL) NewEntries(n int32) (ACLEntry_List, error) {
	l, err := NewACLEntry_List(s.Struct.Segment(), n)
	if err != nil {
		return ACLEntry_List{}, err
	}
	err = s.Struct.SetPtr(0, l.List.ToPtr())
	return l, err
}

// ACL_List is a list of ACL.
type ACL_List struct{ capnp.List }

// NewACL creates a new list of ACL.
func NewACL_List(s *capnp.Segment, sz int32) (ACL_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 0, PointerCount: 1}, sz)
	return ACL_List{l}, err
}

func (s ACL_List) At(i int) ACL { return ACL{s.List.Struct(i)} }

func (s ACL_List) Set(i int, v ACL) error { return s.List.SetStruct(i, v.Struct) }

func (s ACL_List) String() string {
	str, _ := text.MarshalList(0xcd0ebf47910e2043, s.List)
	return str
}

// ACL_Promise is a wrapper for a ACL promised by a client call.
type ACL_Promise struct{ *capnp.Pipeline }

func (p ACL_Promise) Struct() (ACL, error) {
	s, err := p.Pipeline.Struct()
	return ACL{s}, err
}

type ACLEntry struct{ capnp.Struct }

// ACLEntry_TypeID is the unique identifier for the type ACLEntry.
const ACLEntry_TypeID = 0xa6dc68ca349c0b50

func NewACLEntry(s *capnp.Segment) (ACLEntry, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1})
	return ACLEntry{st}, err
}

func NewRootACLEntry(s *capnp.Segment) (ACLEntry, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1})
	return ACLEntry{st}, err
}

func ReadRootACLEntry(msg *capnp.Message) (ACLEntry, error) {
	root, err := msg.RootPtr()
	return ACLEntry{root.Struct()}, err
}

func (s ACLEntry) String() string {
	str, _ := text.Marshal(0xa6dc68ca349c0b50, s.Struct)
	return str
}

func (s ACLEntry) Action() ACLAction {
	return ACLAction(s.Struct.Uint16(0))
}

func (s ACLEntry) SetAction(v ACLAction) {
	s.Struct.SetUint16(0, uint16(v))
}

func (s ACLEntry) Rule() (HopPredicate, error) {
	p, err := s.Struct.Ptr(0)
	return HopPredicate{Struct: p.Struct()}, err
}

func (s ACLEntry) HasRule() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s ACLEntry) SetRule(v HopPredicate) error {
	return s.Struct.SetPtr(0, v.Struct.ToPtr())
}

// NewRule sets the rule field to a newly
// allocated HopPredicate struct, preferring placement in s's segment.
func (s ACLEntry) NewRule() (HopPredicate, error) {
	ss, err := NewHopPredicate(s.Struct.Segment())
	if err != nil {
		return HopPredicate{}, err
	}
	err = s.Struct.SetPtr(0, ss.Struct.ToPtr())
	return ss, err
}

// ACLEntry_List is a list of ACLEntry.
type ACLEntry_List struct{ capnp.List }

// NewACLEntry creates a new list of ACLEntry.
func NewACLEntry_List(s *capnp.Segment, sz int32) (ACLEntry_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1}, sz)
	return ACLEntry_List{l}, err
}

func (s ACLEntry_List) At(i int) ACLEntry { return ACLEntry{s.List.Struct(i)} }

func (s ACLEntry_List) Set(i int, v ACLEntry) error { return s.List.SetStruct(i, v.Struct) }

func (s ACLEntry_List) String() string {
	str, _ := text.MarshalList(0xa6dc68ca349c0b50, s.List)
	return str
}

// ACLEntry_Promise is a wrapper for a ACLEntry promised by a client call.
type ACLEntry_Promise struct{ *capnp.Pipeline }

func (p ACLEntry_Promise) Struct() (ACLEntry, error) {
	s, err := p.Pipeline.Struct()
	return ACLEntry{s}, err
}

func (p ACLEntry_Promise) Rule() HopPredicate_Promise {
	return HopPredicate_Promise{Pipeline: p.Pipeline.GetPipeline(0)}
}

type HopPredicate struct{ capnp.Struct }

// HopPredicate_TypeID is the unique identifier for the type HopPredicate.
const HopPredicate_TypeID = 0xae43a4f525738ee0

func NewHopPredicate(s *capnp.Segment) (HopPredicate, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1})
	return HopPredicate{st}, err
}

func NewRootHopPredicate(s *capnp.Segment) (HopPredicate, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1})
	return HopPredicate{st}, err
}

func ReadRootHopPredicate(msg *capnp.Message) (HopPredicate, error) {
	root, err := msg.RootPtr()
	return HopPredicate{root.Struct()}, err
}

func (s HopPredicate) String() string {
	str, _ := text.Marshal(0xae43a4f525738ee0, s.Struct)
	return str
}

func (s HopPredicate) Isdas() uint64 {
	return s.Struct.Uint64(0)
}

func (s HopPredicate) SetIsdas(v uint64) {
	s.Struct.SetUint64(0, v)
}

func (s HopPredicate) Ifids() (capnp.UInt64List, error) {
	p, err := s.Struct.Ptr(0)
	return capnp.UInt64List{List: p.List()}, err
}

func (s HopPredicate) HasIfids() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s HopPredicate) SetIfids(v capnp.UInt64List) error {
	return s.Struct.SetPtr(0, v.List.ToPtr())
}

// NewIfids sets the ifids field to a newly
// allocated capnp.UInt64List, preferring placement in s's segment.
func (s HopPredicate) NewIfids(n int32) (capnp.UInt64List, error) {
	l, err := capnp.NewUInt64List(s.Struct.Segment(), n)
	if err != nil {
		return capnp.UInt64List{}, err
	}
	err = s.Struct.SetPtr(0, l.List.ToPtr())
	return l, err
}

// HopPredicate_List is a list of HopPredicate.
type HopPredicate_List struct{ capnp.List }

// NewHopPredicate creates a new list of HopPredicate.
func NewHopPredicate_List(s *capnp.Segment, sz int32) (HopPredicate_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1}, sz)
	return HopPredicate_List{l}, err
}

func (s HopPredicate_List) At(i int) HopPredicate { return HopPredicate{s.List.Struct(i)} }

func (s HopPredicate_List) Set(i int, v HopPredicate) error { return s.List.SetStruct(i, v.Struct) }

func (s HopPredicate_List) String() string {
	str, _ := text.MarshalList(0xae43a4f525738ee0, s.List)
	return str
}

// HopPredicate_Promise is a wrapper for a HopPredicate promised by a client call.
type HopPredicate_Promise struct{ *capnp.Pipeline }

func (p HopPredicate_Promise) Struct() (HopPredicate, error) {
	s, err := p.Pipeline.Struct()
	return HopPredicate{s}, err
}

type ACLAction uint16

// ACLAction_TypeID is the unique identifier for the type ACLAction.
const ACLAction_TypeID = 0xc120b3aca8b6ad5e

// Values of ACLAction.
const (
	ACLAction_unset ACLAction = 0
	ACLAction_deny  ACLAction = 1
	ACLAction_allow ACLAction = 2
)

// String returns the enum's constant name.
func (c ACLAction) String() string {
	switch c {
	case ACLAction_unset:
		return "unset"
	case ACLAction_deny:
		return "deny"
	case ACLAction_allow:
		return "allow"

	default:
		return ""
	}
}

// ACLActionFromString returns the enum value with a name,
// or the zero value if there's no such value.
func ACLActionFromString(c string) ACLAction {
	switch c {
	case "unset":
		return ACLAction_unset
	case "deny":
		return ACLAction_deny
	case "allow":
		return ACLAction_allow

	default:
		return 0
	}
}

type ACLAction_List struct{ capnp.List }

func NewACLAction_List(s *capnp.Segment, sz int32) (ACLAction_List, error) {
	l, err := capnp.NewUInt16List(s, sz)
	return ACLAction_List{l.List}, err
}

func (l ACLAction_List) At(i int) ACLAction {
	ul := capnp.UInt16List{List: l.List}
	return ACLAction(ul.At(i))
}

func (l ACLAction_List) Set(i int, v ACLAction) {
	ul := capnp.UInt16List{List: l.List}
	ul.Set(i, uint16(v))
}

const schema_e45bfd61f120454d = "x\xda\x84\x93\xc1K\x14a\x18\xc6\x9f\xe7\x9d\xb5UR" +
	"w\xc7Q\xb2C\xac\x88\x81\x09\x85-\x9e$X\xcdD" +
	"\x0b\xc3\xfd\xa0CP\x14\xd3\xec\xd4\x0e,3\xd3\xce\x98" +
	"\xec!<y\xe8\x12x\xe8\x10\xd4!\xa8\xe8\x90E\x06" +
	"]\xa3\xab\xe01\xa2\xe8\x10\xd1?\xe0\xa1C\x81L\xcc" +
	"\xa8;\x8b\xact\x9a\x8f\x97\x87\xf7\xfd\xbd\xf3\xfb\xbe\xf1" +
	"AN\xc9\xd9\x8ec\x02\xa8\xc1\x8e#\xd1\xbd\x81G\xe7" +
	"\xae\xaf\xddZ\x85\xde\xc7\xe8\xf2\xec\xd0\xb6\xb9s\xed\x17" +
	":\xb4,\xa0oo\xea;\xf1\xf7\xcf[0*\x1f}" +
	"2\xb1Y\xfd\xfe\x12\xaa\x8f\xadIf\x01\xe3\x05\xbf\x19" +
	"\xef\x92\xd3:\x97\xc1\xe8\xc7\xc3\xe0\xe4\xef\xe73o\xda" +
	"\x86\xbb\xe4\xaf1 \xf1I\x978|c\xfd\xc3\xab\xd7" +
	"\xef\x87>A\xef\x934\x0b\x1a\xf7\xe5\xa7\xf1 \x09\xae" +
	"\xca\"\x18\xcd\x0c\xf5\xae\xcd}\xec\xdd:\xc0\x9a4}" +
	",\x1b\xc6\xb3$\xfbTJ`\xb4\xf1en\xf8\xea\xe8" +
	"\xf1\xa8-\xc1\x96l\x1a_\x93\xf0\xe7\x84\xc07\xc3\xea" +
	"M\xdf\xab\x89c5\xceX\xa6\xef\xfa\x93e\xaf\xe6X" +
	"\x0d\xa0L\xaan-\x03d\x08\xe8\xb3\xc3\x80\x9a\xd2\xa8" +
	"\x16\x84:\xd9\xcf\xb8x\xf1\x12\xa0\xe65\xaa+B]" +
	"\xa4\x9f\x02\xe8\xea<\xa0\x164\xaa\xaa0kZ5\xe6" +
	"S|\x90y0\x0a\xec\xbbK\xb6k\xd9\x00\xd8\x0da" +
	"7\xb8\xe2\xf9\xa1\xe3\xb9\x01{\xc1\xb2F\xe6\xd3=\xc0" +
	"\xb8\xd8\x0euzfa\xd6\x0d\xb5z#f\xedl\xb2" +
	"\x9e\x9a\x04\xd4\x88F5.\xdcG==\x06\xa8Q\x8d" +
	"jBX2\xadx\x16s\xa9\x00\x9090W_\xaa" +
	"\xd9\xcc\xa7\x12\xf7x\xdb\x8c\x9e\xf7\xfcr\xdd.U\x1c" +
	"\xcb\x0c\xed\x03\xe3\x8bm\xc6\x17\xf7\xc6_\x10\x16\x9c\xa0" +
	"b\x06\xec\x82\xb0\x0b,8\xb7\x9dJs\xed\xb8x\xf8" +
	"\xb2\xd3V\x98u<71\x93\xfc\xeb\x13\xc5\x18Q\x1f" +
	"\x18\x03(zO\x11(,\xb9\x81\x1d\xe6*\xb6\xdb(" +
	"\x98\xb5\x9a\xb7\xdcl\xc5\xfdV\x85\xa4W\xdc$\xd3d" +
	"\xee\x89\xa5ujT#\xc2\x15\xdb\x0d\xeb\x8e\xdd\xa2\xa2" +
	"\xf9\x02\x0eW\xb1\x98\xe8\xdb\xbd5\xff11\xd9bb" +
	"\xd9v\xeeTCf \xcc\x80%?\xb9{\xcc\xa7\x8f" +
	"s\xd7\xc0\xbf\x00\x00\x00\xff\xff\xe4;\xea\xc9"

func init() {
	schemas.Register(schema_e45bfd61f120454d,
		0x8562915c3c951576,
		0xa6dc68ca349c0b50,
		0xae43a4f525738ee0,
		0xc120b3aca8b6ad5e,
		0xcd0ebf47910e2043,
		0xff1928582247d7b2)
}
