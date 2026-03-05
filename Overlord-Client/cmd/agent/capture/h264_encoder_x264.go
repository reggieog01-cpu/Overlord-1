//go:build cgo

package capture

import (
	"bytes"
	"image"
	"sync"

	x264 "github.com/gen2brain/x264-go"
)

var (
	h264Mu     sync.Mutex
	h264Enc    *x264.Encoder
	h264Buf    bytes.Buffer
	h264Width  int
	h264Height int
)

func encodeH264Frame(img *image.RGBA) ([]byte, error) {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	h264Mu.Lock()
	defer h264Mu.Unlock()

	if err := ensureH264EncoderLocked(width, height); err != nil {
		return nil, err
	}

	h264Buf.Reset()
	if err := h264Enc.Encode(img); err != nil {
		return nil, err
	}

	out := make([]byte, h264Buf.Len())
	copy(out, h264Buf.Bytes())
	return out, nil
}

func h264Available() bool {
	return true
}

func ensureH264EncoderLocked(width, height int) error {
	if h264Enc != nil && h264Width == width && h264Height == height {
		return nil
	}

	closeH264EncoderLocked()

	opts := &x264.Options{
		Width:     width,
		Height:    height,
		FrameRate: 25,
		Tune:      "zerolatency",
		Preset:    "ultrafast",
		Profile:   "baseline",
		LogLevel:  x264.LogError,
	}

	enc, err := x264.NewEncoder(&h264Buf, opts)
	if err != nil {
		return err
	}

	h264Enc = enc
	h264Width = width
	h264Height = height
	return nil
}

func resetH264Encoder() {
	h264Mu.Lock()
	defer h264Mu.Unlock()
	closeH264EncoderLocked()
}

func closeH264EncoderLocked() {
	if h264Enc != nil {
		_ = h264Enc.Close()
		h264Enc = nil
	}
	h264Width = 0
	h264Height = 0
	h264Buf.Reset()
}
