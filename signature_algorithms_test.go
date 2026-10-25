package fastls

import (
	"encoding/binary"
	utls "github.com/refraction-networking/utls"
	"reflect"
	"testing"
)

// Inspect serialized ClientHello bytes; checking the preset alone would miss
// uTLS session-controller behavior and the unwanted cold PSK regression.
func helloPayloads(t *testing.T, spec *utls.ClientHelloSpec) map[uint16][]byte {
	t.Helper()
	c := utls.UClient(nil, &utls.Config{ServerName: "localhost", OmitEmptyPsk: true}, utls.HelloCustom)
	if err := c.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := c.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	b := c.HandshakeState.Hello.Raw[4:]
	b = b[34:]
	n := int(b[0])
	b = b[1+n:]
	n = int(binary.BigEndian.Uint16(b))
	b = b[2+n:]
	n = int(b[0])
	b = b[1+n:]
	n = int(binary.BigEndian.Uint16(b))
	b = b[2 : 2+n]
	result := map[uint16][]byte{}
	for len(b) > 0 {
		id := binary.BigEndian.Uint16(b)
		n = int(binary.BigEndian.Uint16(b[2:]))
		result[id] = append([]byte(nil), b[4:4+n]...)
		b = b[4+n:]
	}
	return result
}

func TestCustomFingerprintsDoNotFabricateColdPSK(t *testing.T) {
	ja3 := "771,4865-4866-4867-49195,0-10-11-13-16-35-43-45-51-41,4588-29-23-24,0"
	for _, v := range []string{ja3, regressionJA4R} {
		s, err := StringToSpec(v, regressionUA)
		if err != nil {
			t.Fatal(err)
		}
		p := helloPayloads(t, s)
		if _, ok := p[41]; ok {
			t.Fatal("PSK emitted without a real cached session")
		}
		if len(p[13]) == 0 {
			t.Fatal("missing signature algorithms")
		}
	}
}

func TestJA3ExplicitSignatureDeclarationOnWire(t *testing.T) {
	ja3 := "771,4865-4866-4867-49195,0-10-11-13-16-35-43-45-51,4588-29-23-24,0"
	values := []uint16{0x0904, 0x0905, 0x0906, 0x0403, 0x0804}
	s, err := StringToSpecWithSignatureAlgorithms(ja3, regressionUA, values)
	if err != nil {
		t.Fatal(err)
	}
	values[0] = 0xffff
	p := helloPayloads(t, s)[13]
	var got []uint16
	for i := 2; i < len(p); i += 2 {
		got = append(got, binary.BigEndian.Uint16(p[i:]))
	}
	if !reflect.DeepEqual(got, []uint16{0x0904, 0x0905, 0x0906, 0x0403, 0x0804}) {
		t.Fatal(got)
	}
	for _, bad := range [][]uint16{{}, {0}} {
		if _, err := StringToSpecWithSignatureAlgorithms(ja3, regressionUA, bad); err == nil {
			t.Fatal("accepted invalid list")
		}
	}
}
