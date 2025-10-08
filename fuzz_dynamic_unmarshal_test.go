package fuzzpb

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	_ "embed"
)

var (
	registryOnce          sync.Once
	filesRegistry         *protoregistry.Files
	allMessageDescriptors []protoreflect.MessageDescriptor
	registryLoadErr       error
)

//go:embed descriptor_set.pb
var descBytes []byte

func defaultDescriptorPath() string {
	wd, err := os.Getwd()
	if err != nil {
		return "descriptor_set.pb"
	}
	return filepath.Join(wd, "fuzz", "descriptor_set.pb")
}

func loadDescriptorSet() error {
	var data []byte
	var err error
	if len(descBytes) > 0 {
		data = descBytes
	} else if p := os.Getenv("DESCRIPTOR_SET_PATH"); p != "" {
		data, err = os.ReadFile(p)
		if err != nil {
			return err
		}
	} else {
		path := defaultDescriptorPath()
		data, err = os.ReadFile(path)
		if err != nil {
			return err
		}
	}
	fds := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(data, fds); err != nil {
		return err
	}
	files, err := protodesc.NewFiles(fds)
	if err != nil {
		return err
	}
	filesRegistry = files
	var descriptors []protoreflect.MessageDescriptor
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		collectMessages(fd.Messages(), &descriptors)
		return true
	})
	allMessageDescriptors = descriptors
	return nil
}

func collectMessages(list protoreflect.MessageDescriptors, out *[]protoreflect.MessageDescriptor) {
	for i := 0; i < list.Len(); i++ {
		md := list.Get(i)
		*out = append(*out, md)
		collectMessages(md.Messages(), out)
	}
}

func ensureRegistry(t testing.TB) {
	registryOnce.Do(func() {
		registryLoadErr = loadDescriptorSet()
	})
	if registryLoadErr != nil {
		t.Skipf("descriptor_set.pb not available: %v", registryLoadErr)
	}
	if len(allMessageDescriptors) == 0 {
		t.Skip("no message descriptors found")
	}
	maybeListMessageTypes(t)
}

func pickMessageDescriptorByIndex(idx int) protoreflect.MessageDescriptor {
	if len(allMessageDescriptors) == 0 {
		return nil
	}
	return allMessageDescriptors[idx%len(allMessageDescriptors)]
}

// pickMessageDescriptorSpread selects message descriptor by index and a bit of
// entropy from data to evenly cover when engine hasn't diversified idx.
func pickMessageDescriptorSpread(idx int, data []byte) protoreflect.MessageDescriptor {
	if len(allMessageDescriptors) == 0 {
		return nil
	}
	if len(data) == 0 {
		return pickMessageDescriptorByIndex(idx)
	}
	// Mix first 2 bytes (if any) to create distributed offset.
	var mix uint32
	if len(data) >= 2 {
		mix = uint32(data[0])<<8 | uint32(data[1])
	} else {
		mix = uint32(data[0])
	}
	base := idx % len(allMessageDescriptors)
	off := int(mix) % len(allMessageDescriptors)
	return allMessageDescriptors[(base+off)%len(allMessageDescriptors)]
}

var listOnce sync.Once

func maybeListMessageTypes(t testing.TB) {
	if os.Getenv("FUZZ_LIST_TYPES") == "" {
		return
	}
	listOnce.Do(func() {
		names := make([]string, 0, len(allMessageDescriptors))
		for _, md := range allMessageDescriptors {
			names = append(names, string(md.FullName()))
		}
		t.Logf("Loaded %d message types:\n%s", len(names), strings.Join(names, "\n"))
	})
}

func Fuzz_DynamicUnmarshal(f *testing.F) {
	f.Add(uint8(0), []byte{})
	f.Add(uint8(1), []byte{0x0a, 0x00})
	f.Add(uint8(2), []byte{0x08, 0x01})

	f.Fuzz(func(t *testing.T, idx uint8, data []byte) {
		ensureRegistry(t)

		// guard against gigantic inputs under mutation to avoid DoS on CI
		if len(data) > (1 << 20) { // 1 MiB
			t.Skip("input too large, skipping")
		}

		// safety against unexpected panics in parser
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic in unmarshal/marshal pipeline: %v", r)
			}
		}()

		// Evenly spread coverage between message types
		md := pickMessageDescriptorSpread(int(idx), data)
		if md == nil {
			t.Skip("no message descriptor")
		}
		msg := dynamicpb.NewMessage(md)

		if err := proto.Unmarshal(data, msg); err != nil {
			return // reject malformed is expected
		}
		out, err := proto.Marshal(msg)
		if err != nil {
			t.Fatalf("marshal after unmarshal failed: %v", err)
		}
		// second round-trip to catch edge-case inconsistencies
		msg2 := dynamicpb.NewMessage(md)
		if err := proto.Unmarshal(out, msg2); err != nil {
			t.Fatalf("second unmarshal failed: %v", err)
		}
		if _, err := proto.Marshal(msg2); err != nil {
			t.Fatalf("second marshal failed: %v", err)
		}

		// Stress concurrently: Clone/Merge/Marshal on independent copies to
		// uncover race hidden in dynamicpb/proto when receiving malicious data.
		var wg sync.WaitGroup
		errCh := make(chan error, 3)
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				clone := proto.Clone(msg)
				_ = clone
				// Marshal copy
				if _, err := proto.Marshal(clone); err != nil {
					// Marshal error on copy after successful marshal is suspicious
					errCh <- fmt.Errorf("concurrent marshal failed: %w", err)
				}
				// Merge into an empty message of the same type
				dst := dynamicpb.NewMessage(md)
				proto.Merge(dst, clone)
			}()
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			if err != nil {
				t.Fatalf("concurrency stress error: %v", err)
			}
		}
	})
}

// Fuzz_UnmarshalOptions: try all combinations of UnmarshalOptions to catch unknown/partial handling errors.
func Fuzz_UnmarshalOptions(f *testing.F) {
	f.Add(uint8(0), []byte{})
	f.Add(uint8(1), []byte{0x0a, 0x00})
	f.Add(uint8(2), []byte{0x08, 0x01})

	f.Fuzz(func(t *testing.T, idx uint8, data []byte) {
		ensureRegistry(t)
		if len(data) > (1 << 20) {
			t.Skip("input too large, skipping")
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic in unmarshal options pipeline: %v", r)
			}
		}()

		md := pickMessageDescriptorSpread(int(idx), data)
		if md == nil {
			t.Skip("no message descriptor")
		}

		opts := []proto.UnmarshalOptions{
			{DiscardUnknown: false, AllowPartial: false},
			{DiscardUnknown: true, AllowPartial: false},
			{DiscardUnknown: false, AllowPartial: true},
			{DiscardUnknown: true, AllowPartial: true},
		}
		for _, opt := range opts {
			msg := dynamicpb.NewMessage(md)
			if err := opt.Unmarshal(data, msg); err != nil {
				// error is normal; continue with different options
				continue
			}
			if _, err := proto.Marshal(msg); err != nil {
				t.Fatalf("marshal after options unmarshal failed (%+v): %v", opt, err)
			}
		}
	})
}

// Fuzz_DynamicProtoJSON: fuzz mapping JSON <-> Protobuf for every message type.
func Fuzz_DynamicProtoJSON(f *testing.F) {
	f.Add(uint8(0), []byte("{}"))
	f.Add(uint8(1), []byte("{\"unknown\":1}"))
	f.Add(uint8(2), []byte("[]"))

	f.Fuzz(func(t *testing.T, idx uint8, jsonData []byte) {
		ensureRegistry(t)
		if len(jsonData) > (1 << 20) {
			t.Skip("input too large, skipping")
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic in protojson pipeline: %v", r)
			}
		}()

		md := pickMessageDescriptorSpread(int(idx), jsonData)
		if md == nil {
			t.Skip("no message descriptor")
		}
		msg := dynamicpb.NewMessage(md)

		// Two configurations: strict and allow unknown.
		umStrict := protojson.UnmarshalOptions{DiscardUnknown: false}
		umLoose := protojson.UnmarshalOptions{DiscardUnknown: true}

		// Try strict first; if fail, try loose.
		if err := umStrict.Unmarshal(jsonData, msg); err != nil {
			if err2 := umLoose.Unmarshal(jsonData, msg); err2 != nil {
				return // JSON not valid for this message
			}
		}

		// Marshal again (two modes) and round-trip JSON -> PB -> JSON
		mo1 := protojson.MarshalOptions{EmitUnpopulated: false, UseProtoNames: false}
		mo2 := protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}
		if _, err := mo1.Marshal(msg); err != nil {
			t.Fatalf("protojson marshal failed: %v", err)
		}
		if out2, err := mo2.Marshal(msg); err == nil {
			// Unmarshal again the generated JSON to check basic consistency
			msg2 := dynamicpb.NewMessage(md)
			_ = protojson.UnmarshalOptions{DiscardUnknown: false}.Unmarshal(out2, msg2)
		}
	})
}

// Fuzz_GRPCFrameDecode: fuzz layer length-prefixed frame (gRPC) before Unmarshal.
// Frame format: 1 byte compressed flag | 4 bytes big-endian length | payload
func Fuzz_GRPCFrameDecode(f *testing.F) {
	// seed: empty payload frame, uncompressed
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
	// seed: tiny payload (tag 1, length 0)
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x02, 0x0a, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		ensureRegistry(t)
		if len(data) > (1 << 20) {
			t.Skip("input too large, skipping")
		}
		if len(data) < 5 {
			return
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic in gRPC frame decode: %v", r)
			}
		}()

		compressed := data[0]&0x01 == 0x01
		_ = compressed // currently not handling compression in harness
		declared := binary.BigEndian.Uint32(data[1:5])

		// if length is greater than remaining buffer, skip
		if int(declared) > len(data)-5 {
			return
		}
		payload := data[5 : 5+declared]
		if len(payload) == 0 {
			return
		}

		// Use frame header data to select message to avoid coverage shift
		sel := int(data[0])
		md := pickMessageDescriptorSpread(sel, payload)
		if md == nil {
			t.Skip("no message descriptor")
		}
		msg := dynamicpb.NewMessage(md)
		if err := proto.Unmarshal(payload, msg); err != nil {
			return
		}
		if _, err := proto.Marshal(msg); err != nil {
			t.Fatalf("marshal after frame decode failed: %v", err)
		}
	})
}
