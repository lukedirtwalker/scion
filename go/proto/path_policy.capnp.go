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

type ExtPolicy struct{ capnp.Struct }

// ExtPolicy_TypeID is the unique identifier for the type ExtPolicy.
const ExtPolicy_TypeID = 0xd4de36af92a5d3b7

func NewExtPolicy(s *capnp.Segment) (ExtPolicy, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2})
	return ExtPolicy{st}, err
}

func NewRootExtPolicy(s *capnp.Segment) (ExtPolicy, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2})
	return ExtPolicy{st}, err
}

func ReadRootExtPolicy(msg *capnp.Message) (ExtPolicy, error) {
	root, err := msg.RootPtr()
	return ExtPolicy{root.Struct()}, err
}

func (s ExtPolicy) String() string {
	str, _ := text.Marshal(0xd4de36af92a5d3b7, s.Struct)
	return str
}

func (s ExtPolicy) Extends() (capnp.TextList, error) {
	p, err := s.Struct.Ptr(0)
	return capnp.TextList{List: p.List()}, err
}

func (s ExtPolicy) HasExtends() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s ExtPolicy) SetExtends(v capnp.TextList) error {
	return s.Struct.SetPtr(0, v.List.ToPtr())
}

// NewExtends sets the extends field to a newly
// allocated capnp.TextList, preferring placement in s's segment.
func (s ExtPolicy) NewExtends(n int32) (capnp.TextList, error) {
	l, err := capnp.NewTextList(s.Struct.Segment(), n)
	if err != nil {
		return capnp.TextList{}, err
	}
	err = s.Struct.SetPtr(0, l.List.ToPtr())
	return l, err
}

func (s ExtPolicy) Policy() (Policy, error) {
	p, err := s.Struct.Ptr(1)
	return Policy{Struct: p.Struct()}, err
}

func (s ExtPolicy) HasPolicy() bool {
	p, err := s.Struct.Ptr(1)
	return p.IsValid() || err != nil
}

func (s ExtPolicy) SetPolicy(v Policy) error {
	return s.Struct.SetPtr(1, v.Struct.ToPtr())
}

// NewPolicy sets the policy field to a newly
// allocated Policy struct, preferring placement in s's segment.
func (s ExtPolicy) NewPolicy() (Policy, error) {
	ss, err := NewPolicy(s.Struct.Segment())
	if err != nil {
		return Policy{}, err
	}
	err = s.Struct.SetPtr(1, ss.Struct.ToPtr())
	return ss, err
}

// ExtPolicy_List is a list of ExtPolicy.
type ExtPolicy_List struct{ capnp.List }

// NewExtPolicy creates a new list of ExtPolicy.
func NewExtPolicy_List(s *capnp.Segment, sz int32) (ExtPolicy_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2}, sz)
	return ExtPolicy_List{l}, err
}

func (s ExtPolicy_List) At(i int) ExtPolicy { return ExtPolicy{s.List.Struct(i)} }

func (s ExtPolicy_List) Set(i int, v ExtPolicy) error { return s.List.SetStruct(i, v.Struct) }

func (s ExtPolicy_List) String() string {
	str, _ := text.MarshalList(0xd4de36af92a5d3b7, s.List)
	return str
}

// ExtPolicy_Promise is a wrapper for a ExtPolicy promised by a client call.
type ExtPolicy_Promise struct{ *capnp.Pipeline }

func (p ExtPolicy_Promise) Struct() (ExtPolicy, error) {
	s, err := p.Pipeline.Struct()
	return ExtPolicy{s}, err
}

func (p ExtPolicy_Promise) Policy() Policy_Promise {
	return Policy_Promise{Pipeline: p.Pipeline.GetPipeline(1)}
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

func (s Option) Policy() (ExtPolicy, error) {
	p, err := s.Struct.Ptr(0)
	return ExtPolicy{Struct: p.Struct()}, err
}

func (s Option) HasPolicy() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s Option) SetPolicy(v ExtPolicy) error {
	return s.Struct.SetPtr(0, v.Struct.ToPtr())
}

// NewPolicy sets the policy field to a newly
// allocated ExtPolicy struct, preferring placement in s's segment.
func (s Option) NewPolicy() (ExtPolicy, error) {
	ss, err := NewExtPolicy(s.Struct.Segment())
	if err != nil {
		return ExtPolicy{}, err
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

func (p Option_Promise) Policy() ExtPolicy_Promise {
	return ExtPolicy_Promise{Pipeline: p.Pipeline.GetPipeline(0)}
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

const schema_e45bfd61f120454d = "x\xda\x84S\xcfk\x13a\x10\x9d7\x9b\x9a\x16\xd3&" +
	"\xdbm\x0f\x82%\xa5\xb4\xd0\x16\x94\x1a\xaaH\xb1\xa4?" +
	"\x0c\xadZi>\xf0 (\xca\xbaY\xcd\xc2\xba\xbb&" +
	"\x1b\xdb\x9cz\xf2*T\xf0\xe6QEA-V\xd4\xa3" +
	"x\xf0`\xa1\x07Q\x10EE\x8a\xff\x80\x07\x0f\x0a\xb2" +
	"\xb2_\xdal\x08)\xde\x86\xe11\xef\xcd\xbc7c\xa7" +
	"0\xc5\x87\xda\\&\x12\xfb\xdb\xf6\x04\xd7{o\x1f;" +
	"\xbfz\xe9\x06\xa9\xdd\x08N\xe7\xfa\x7f\xea\x7f\xcf\xfd\xa0" +
	"6%N\xa4\xf5aC\x1bAX\x0da\x8d\x10\xe4\xf7" +
	"\xde\x19\xdf(~\xb9O\xa2\x1b\x8d`\x09y\x87\xcf\xda" +
	"WY}\xc2\x12!\xf8~\xb3<\xf4\xeb\xee\xec\x93\x96" +
	"\xe0\xc3\xfcG\x9b\xe6\xb0\x9a\xe4\x10|\xe1\xf1\x8b\x07\x8f" +
	"\x9e\xf5\xbf&\xb5\x9b#,A{\xc8[\xdas\x09|" +
	"\xca\x8b\x84`\xb6\xbfku\xeeU\xd7f\x93\\9\xf4" +
	"\x0d\xafk\x9b\x12\xfb\x96\xb3\x84\xe0\xe5\xfb{\xb7\xd6\x8e" +
	"|\xfb\xd0\x84\x95\x88\xdf\xbc\xa5\xd5\x96\x84\x12\x0aX\xff" +
	"87pvx_\xd0R\xedUeC\xabJpE" +
	"\x82=\xdd/^\xf4\\\x9b-\xa3z\xd0\xd0=\xc7\x9b" +
	"\xc8\xbb\xb6eT\x89\xf2\x80H(1\xa2\x18\x88\xd4\xdc" +
	"\x00\x91\x98R \x16\x18*\xd0\x83\xb0y\xe2$\x91\x98" +
	"W \xce0T\xe6\x1e0\x91*f\x88\xc4\x82\x02Q" +
	"d\xc4u\xc3F*Z\x95\x80\x14!(\x9b\xd7*\xa6" +
	"c\x98D\x84\x041\x12\x84\x15\xd7\xf3-\xd7)\xa3\x8b" +
	"\x90W\x80T\xb4\x07!l\xb6\x92:=\xbb\x90s|" +
	"\xa5T\x0d\xb5\xb6\xd7\xb5\x8eL\x10\x89A\x05b\x8c\xb1" +
	"#\xf5\xc0(\x91\x18V \xc6\x19Y\xdd\x08\xb9\x90\x8c" +
	"\xcc\" IH\x96*\xb6\x89Td\xf8\xb6\xde\x16\xd4" +
	"\xf3\xae\x97/\x99\xd9\x82e\xe8\xbe\xd9D\x9fiA\x9f" +
	"\xd9\xa6?\xceH[\xe5\x82^F\x071:\x08i\xeb" +
	"\xb2U\xa8\xaf\x1d6w_v\xda\xf0\xe3\x96\xebHg" +
	"\xe4\xad\xfb2\xa1D\xb5w\x94\x08\xacvf\x88\xd2\x15" +
	"\xa7l\xfa\xc9\x82\xe9T\xd3\xbam\xbbK\xf5Q\xd8\x19" +
	"\x95\x96\xb3\xc2!\xb1\xba\xe6\xce\xd0\xb4v\x05b\x90\xb1" +
	"b:~\xc92\x1b\xac\xa8\x7f\xcb\xeeV\xe4\x96\xfd\xbc" +
	"k\xc7-\xa3\xd9\x8b\x99\xedcL5\xe4f24\xe8" +
	"h\xed\x1a+\xe6\xb2o:\xd1\x05\x12\xb5\x0bd=\x19" +
	"C\xa4\xa2\xb7\xde\xdd\x8cE\x99\x9dZd\xff\x13\x83\x89" +
	"\x86\x18,\x99\xd6\x95\xa2\x8f\x181b\x8d\x8c\xf5o\xab" +
	"1\xfe\x0b\x00\x00\xff\xff-%\x15l"

func init() {
	schemas.Register(schema_e45bfd61f120454d,
		0x8562915c3c951576,
		0xa6dc68ca349c0b50,
		0xae43a4f525738ee0,
		0xc120b3aca8b6ad5e,
		0xcd0ebf47910e2043,
		0xd4de36af92a5d3b7,
		0xff1928582247d7b2)
}