package tlsfp

import "testing"

func TestRejectsNonTLS(t *testing.T) {
	if _, err := ParseJA3([]byte("GET / HTTP/1.1\r\n")); err == nil {
		t.Fatal("expected error for plaintext HTTP")
	}
}

func TestGREASE(t *testing.T) {
	if !isGREASE(0x0a0a) || !isGREASE(0xfafa) || isGREASE(0x1301) {
		t.Fatal("GREASE detection wrong")
	}
}

// TODO: add real ClientHello vectors (curl, Chrome, Firefox, python-requests)
// under testdata/ and assert known JA3 hashes.
