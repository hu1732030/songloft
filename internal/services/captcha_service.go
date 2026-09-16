package services

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"strings"
	"sync"
	"time"

	"songloft/internal/models"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

const (
	captchaTTL      = 5 * time.Minute
	captchaCodeLen  = 4
	captchaCharset  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	captchaImgW     = 140
	captchaImgH     = 48
	captchaMaxStore = 10000
)

// CaptchaPayload 图形验证码响应。
type CaptchaPayload struct {
	CaptchaID string `json:"captcha_id"`
	Image     string `json:"image"` // data:image/png;base64,...
}

type captchaEntry struct {
	code      string
	expiresAt time.Time
}

// CaptchaService 内存图形验证码（一次性、短 TTL）。
type CaptchaService struct {
	mu    sync.Mutex
	store map[string]captchaEntry
}

// NewCaptchaService 创建验证码服务。
func NewCaptchaService() *CaptchaService {
	return &CaptchaService{store: make(map[string]captchaEntry)}
}

// Generate 生成新验证码图片。
func (s *CaptchaService) Generate() (*CaptchaPayload, error) {
	code, err := randomCaptchaCode(captchaCodeLen)
	if err != nil {
		return nil, err
	}
	id, err := randomCaptchaID()
	if err != nil {
		return nil, err
	}
	imgBytes, err := renderCaptchaPNG(code)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.cleanupLocked()
	if len(s.store) >= captchaMaxStore {
		s.mu.Unlock()
		return nil, models.ErrCaptchaInvalid
	}
	s.store[id] = captchaEntry{
		code:      code,
		expiresAt: time.Now().Add(captchaTTL),
	}
	s.mu.Unlock()

	return &CaptchaPayload{
		CaptchaID: id,
		Image:     "data:image/png;base64," + base64.StdEncoding.EncodeToString(imgBytes),
	}, nil
}

// Verify 校验并作废验证码（一次性）。
func (s *CaptchaService) Verify(id, code string) error {
	id = strings.TrimSpace(id)
	code = strings.TrimSpace(code)
	if id == "" || code == "" {
		return models.ErrCaptchaInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()

	entry, ok := s.store[id]
	delete(s.store, id)
	if !ok || time.Now().After(entry.expiresAt) {
		return models.ErrCaptchaInvalid
	}
	if !strings.EqualFold(code, entry.code) {
		return models.ErrCaptchaInvalid
	}
	return nil
}

func (s *CaptchaService) cleanupLocked() {
	now := time.Now()
	for k, v := range s.store {
		if now.After(v.expiresAt) {
			delete(s.store, k)
		}
	}
}

func randomCaptchaID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomCaptchaCode(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = captchaCharset[int(b[i])%len(captchaCharset)]
	}
	return string(out), nil
}

func renderCaptchaPNG(code string) ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, captchaImgW, captchaImgH))
	bg := color.RGBA{R: 245, G: 247, B: 250, A: 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{C: bg}, image.Point{}, draw.Src)

	// 干扰线
	noiseSeed := []byte(code)
	for i := 0; i < 6; i++ {
		c := color.RGBA{
			R: 160 + uint8((noiseSeed[i%len(noiseSeed)]*uint8(i+3))%60),
			G: 160 + uint8((noiseSeed[(i+1)%len(noiseSeed)]*uint8(i+5))%60),
			B: 170 + uint8((noiseSeed[(i+2)%len(noiseSeed)]*uint8(i+7))%50),
			A: 255,
		}
		y1 := 8 + int(noiseSeed[i%len(noiseSeed)])%32
		y2 := 8 + int(noiseSeed[(i+2)%len(noiseSeed)])%32
		drawLine(img, 4, y1, captchaImgW-4, y2, c)
	}

	face := basicfont.Face7x13
	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(color.RGBA{R: 40, G: 48, B: 64, A: 255}),
		Face: face,
	}

	// 放大绘制：每个字符画成约 2x 的像素块
	startX := 18
	for i, ch := range code {
		x := startX + i*28
		y := 30 + int(math.Sin(float64(i))*3)
		d.Dot = fixed.P(x, y)
		d.DrawString(string(ch))
		// 再偏移画一次，加粗
		d.Dot = fixed.P(x+1, y)
		d.DrawString(string(ch))
		d.Dot = fixed.P(x, y+1)
		d.DrawString(string(ch))
	}

	// 噪点
	for i := 0; i < 80; i++ {
		x := (int(noiseSeed[i%len(noiseSeed)])*13 + i*17) % captchaImgW
		y := (int(noiseSeed[(i+1)%len(noiseSeed)])*11 + i*19) % captchaImgH
		img.Set(x, y, color.RGBA{R: 100, G: 110, B: 130, A: 255})
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func drawLine(img *image.RGBA, x0, y0, x1, y1 int, c color.Color) {
	dx := abs(x1 - x0)
	dy := abs(y1 - y0)
	sx, sy := 1, 1
	if x0 > x1 {
		sx = -1
	}
	if y0 > y1 {
		sy = -1
	}
	err := dx - dy
	for {
		img.Set(x0, y0, c)
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * err
		if e2 > -dy {
			err -= dy
			x0 += sx
		}
		if e2 < dx {
			err += dx
			y0 += sy
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
