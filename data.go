package sss

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"

	"github.com/andybalholm/brotli"
)

const (
	hashLen = 32
	minLen  = 1 + 2 + hashLen

	Version1 = 0
)

var (
	ErrInvalidFormat = errors.New("invalid format")
	ErrNotSigned     = errors.New("not signed")
)

type SSString struct {
	Version    int
	IsCompress bool
	Text       []byte
	HMAC       string
}

func (s *SSString) ToSSS(opt *Option) string {
	if opt == nil {
		opt = DefaultOption()
	}

	var text []byte
	is_compress := false
	{
		buf := &bytes.Buffer{}

		w := brotli.NewWriterOptions(buf, brotli.WriterOptions{
			Quality: brotli.BestCompression,
		})
		_, _ = io.Copy(w, bytes.NewReader(s.Text))
		_ = w.Close()
		if len(buf.Bytes()) > len(s.Text) {
			text = s.Text
		} else {
			text = buf.Bytes()
			is_compress = true
		}
	}

	pkt_len := minLen + len(text)
	b := make([]byte, pkt_len)

	idx := 0
	flag := byte(Version1) << 1
	if is_compress {
		flag |= 0b0001
	} else {
		flag &= 0b1111_1110
	}
	b[idx] = flag
	idx += 1

	binary.BigEndian.PutUint16(b[idx:], uint16(len(text)))
	idx += 2

	copy(b[idx:], text)
	idx += len(text)

	h := hmac.New(sha256.New, opt.Key)
	h.Write(b[:idx])
	sign_calc := h.Sum(nil)
	copy(b[idx:], sign_calc)

	return base64.URLEncoding.EncodeToString(b)
}

func (s *SSString) FromSSS(stext string, opt *Option) error {
	if opt == nil {
		opt = DefaultOption()
	}
	b, err := base64.URLEncoding.DecodeString(stext)
	if err != nil {
		return err
	}
	if len(b) < minLen {
		return ErrInvalidFormat
	}
	idx := 0

	flag := b[idx]
	if flag&0b0000_0001 > 0 {
		s.IsCompress = true
	} else {
		s.IsCompress = false
	}
	s.Version = int(flag&0b0001_1110) >> 1
	idx += 1

	text_len := int(binary.BigEndian.Uint16(b[idx:]))
	idx += 2

	if len(b) < minLen+text_len {
		return ErrInvalidFormat
	}

	text := b[idx : idx+text_len]
	idx += text_len

	sign_pkt := b[idx : idx+hashLen]
	h := hmac.New(sha256.New, opt.Key)

	h.Write(b[:idx])
	sign_calc := h.Sum(nil)
	if !bytes.Equal(sign_pkt, sign_calc) {
		return ErrNotSigned
	}

	if s.IsCompress {
		dst := &bytes.Buffer{}
		r := brotli.NewReader(bytes.NewReader(text))
		_, _ = io.Copy(dst, r)
		b_text_dec := dst.Bytes()
		s.Text = make([]byte, len(b_text_dec))
		copy(s.Text, b_text_dec)
	} else {
		s.Text = make([]byte, len(text))
		copy(s.Text, text)
	}
	return nil
}

func ToSSString(input string, opt *Option) string {
	p := &SSString{}
	p.Text = []byte(input)
	return p.ToSSS(opt)
}

func FromSSString(sss string, opt *Option) (string, error) {
	p := &SSString{}
	err := p.FromSSS(sss, opt)
	return string(p.Text), err
}
