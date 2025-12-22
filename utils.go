package fastls

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	utls "github.com/refraction-networking/utls"
)

const (
	chrome  = "chrome"  // Chrome 浏览器类型
	firefox = "firefox" // Firefox 浏览器类型
	other   = "other"   // 其他浏览器类型
)

func parseUserAgent(userAgent string) string {
	lowerUA := strings.ToLower(userAgent)
	if strings.Contains(lowerUA, "firefox") {
		return firefox
	}
	for _, keyword := range []string{"chrome/", "chromium/", "crios/", "edgi/", "edg/"} {
		if strings.Contains(lowerUA, keyword) {
			return chrome
		}
	}
	return other
}

// DecompressBody 解压缩响应体数据
func DecompressBody(Body []byte, encoding []string, content []string) (parsedBody string) {
	if len(encoding) > 0 {
		if encoding[0] == "gzip" {
			unz, err := gUnzipData(Body)
			if err != nil {
				return string(Body)
			}
			return string(unz)
		} else if encoding[0] == "deflate" {
			unz, err := enflateData(Body)
			if err != nil {
				return string(Body)
			}
			return string(unz)
		} else if encoding[0] == "br" {
			unz, err := unBrotliData(Body)
			if err != nil {
				return string(Body)
			}
			return string(unz)
		} else if encoding[0] == "zstd" {
			unz, err := unZstdData(Body)
			if err != nil {
				return string(Body)
			}
			return string(unz)
		}
	} else if len(content) > 0 {
		decodingTypes := map[string]bool{
			"image/svg+xml":   true,
			"image/webp":      true,
			"image/jpeg":      true,
			"image/png":       true,
			"image/gif":       true,
			"image/avif":      true,
			"application/pdf": true,
		}
		if decodingTypes[content[0]] {
			return base64.StdEncoding.EncodeToString(Body)
		}
	}
	parsedBody = string(Body)
	return parsedBody
}

func gUnzipData(data []byte) (resData []byte, err error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return []byte{}, err
	}
	defer gz.Close()
	respBody, err := io.ReadAll(gz)
	return respBody, err
}
func enflateData(data []byte) (resData []byte, err error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return []byte{}, err
	}
	defer zr.Close()
	enflated, err := io.ReadAll(zr)
	return enflated, err
}
func unBrotliData(data []byte) (resData []byte, err error) {
	br := brotli.NewReader(bytes.NewReader(data))
	respBody, err := io.ReadAll(br)
	return respBody, err
}

func unZstdData(data []byte) ([]byte, error) {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return dec.DecodeAll(data, nil)
}

// StringToSpec 将指纹字符串转换为 uTLS ClientHelloSpec
func StringToSpec(fingerprint string, userAgent string) (*utls.ClientHelloSpec, error) {
	// 检查是否为 JA4R 格式: t13d<num>_<cipher_suites>_<extensions>_<signature_algorithms>
	if strings.HasPrefix(fingerprint, "t") && strings.Count(fingerprint, "_") >= 3 {
		return ParseJA4R(fingerprint, userAgent)
	}
	// 处理 JA3 格式
	ja3 := fingerprint
	browserType := parseUserAgent(userAgent)
	tokens := strings.Split(ja3, ",")

	// 验证 JA3 格式：至少需要 5 个部分（version, ciphers, extensions, curves, point_formats）
	if len(tokens) < 5 {
		return nil, fmt.Errorf("JA3 格式错误: 需要至少5个部分（用逗号分隔），得到 %d 个部分: %s", len(tokens), fingerprint)
	}

	version := tokens[0]
	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")

	// 检查是否包含 PSK 扩展（扩展ID 41）
	includePSK := false
	for _, ext := range extensions {
		if ext == "41" {
			includePSK = true
			break
		}
	}

	extMap := buildTLSExtensionMap(browserType, includePSK)
	curves := strings.Split(tokens[3], "-")
	if len(curves) == 1 && curves[0] == "" {
		curves = []string{}
	}
	pointFormats := strings.Split(tokens[4], "-")
	if len(pointFormats) == 1 && pointFormats[0] == "" {
		pointFormats = []string{}
	}
	// 解析椭圆曲线
	var targetCurves []utls.CurveID
	if browserType == chrome {
		targetCurves = append(
			targetCurves,
			utls.CurveID(utls.GREASE_PLACEHOLDER),
		)
	}

	for _, c := range curves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		targetCurves = append(targetCurves, utls.CurveID(cid))
	}

	extMap["10"] = &utls.SupportedCurvesExtension{Curves: targetCurves}

	// 解析点格式
	var targetPointFormats []byte
	for _, p := range pointFormats {
		pid, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, err
		}
		targetPointFormats = append(targetPointFormats, byte(pid))
	}

	// 检查是否包含扩展11
	hasExtension11 := false
	for _, e := range extensions {
		if e == "11" {
			hasExtension11 = true
			break
		}
	}

	// 点格式不为空时，必须设置扩展11才能发送点格式信息
	if len(targetPointFormats) > 0 {
		// 检查原始输入的最后一个点格式，如果已包含 "0" 则不自动添加
		originalLastPointFormat := ""
		if len(pointFormats) > 0 {
			originalLastPointFormat = pointFormats[len(pointFormats)-1]
		}

		// 保持原始输入的精确性，不自动添加 0
		if originalLastPointFormat != "0" && targetPointFormats[len(targetPointFormats)-1] != 0 {
			// 不自动添加 0，保持原始设置的精确性
		}
		// 设置扩展11以发送点格式信息
		extMap["11"] = &utls.SupportedPointsExtension{SupportedPoints: targetPointFormats}
		// 如果扩展列表中还没有 "11"，需要添加
		if !hasExtension11 {
			// 在 "10" 之后插入 "11"
			newExtensions := make([]string, 0, len(extensions)+1)
			inserted := false
			for _, e := range extensions {
				if e == "10" && !inserted {
					newExtensions = append(newExtensions, e)
					newExtensions = append(newExtensions, "11")
					inserted = true
				} else {
					newExtensions = append(newExtensions, e)
				}
			}
			// 如果未找到 "10"，在 PSK (41) 之前插入
			if !inserted {
				foundPSK := false
				for i, e := range extensions {
					if e == "41" {
						newExtensions = make([]string, 0, len(extensions)+1)
						newExtensions = append(newExtensions, extensions[:i]...)
						newExtensions = append(newExtensions, "11")
						newExtensions = append(newExtensions, extensions[i:]...)
						foundPSK = true
						break
					}
				}
				if !foundPSK {
					newExtensions = append(extensions, "11")
				}
			}
			extensions = newExtensions
		}
	}

	// 设置扩展43（支持的TLS版本）
	ver, err := strconv.ParseUint(version, 10, 16)
	if err != nil {
		return nil, err
	}
	tlsMaxVersion, tlsMinVersion, tlsExtension, err := createTlsVersion(uint16(ver), browserType)
	if err != nil {
		return nil, err
	}
	extMap["43"] = tlsExtension

	// 构建扩展列表，PSK扩展（41）必须放在最后
	var exts []utls.TLSExtension
	var pskExt utls.TLSExtension

	// Chrome 浏览器添加 GREASE 扩展
	if browserType == chrome {
		exts = append(exts, &utls.UtlsGREASEExtension{
			Body: []byte{},
		})
	}

	// 添加所有非PSK扩展，PSK扩展单独处理
	for _, e := range extensions {
		if e == "41" {
			// PSK扩展保存到后面处理
			te, ok := extMap[e]
			if !ok {
				return nil, raiseExtensionError(e)
			}
			pskExt = te
			continue
		}
		te, ok := extMap[e]
		if !ok {
			return nil, raiseExtensionError(e)
		}
		exts = append(exts, te)
	}

	// Chrome 的最后一个 GREASE 扩展放在 PSK 之前（如果存在PSK）
	if browserType == chrome && pskExt != nil {
		exts = append(exts, &utls.UtlsGREASEExtension{
			Body: []byte{},
		})
	}

	// PSK扩展放在最后
	if pskExt != nil {
		exts = append(exts, pskExt)
	}

	// 构建密码套件列表
	var suites []uint16
	// Chrome 浏览器添加 GREASE 占位符
	if browserType == chrome {
		suites = append(suites, utls.GREASE_PLACEHOLDER)
	}
	for _, c := range ciphers {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		suites = append(suites, uint16(cid))
	}
	return &utls.ClientHelloSpec{
		TLSVersMin:         tlsMinVersion,
		TLSVersMax:         tlsMaxVersion,
		CipherSuites:       suites,
		CompressionMethods: []byte{0},
		Extensions:         exts,
		GetSessionID:       sha256.Sum256,
	}, nil
}

// createTlsVersion 创建 TLS 版本扩展
func createTlsVersion(ver uint16, browserType string) (tlsMaxVersion uint16, tlsMinVersion uint16, tlsSupport utls.TLSExtension, err error) {
	// 根据浏览器类型构建版本列表，Chrome 添加 GREASE 占位符
	buildVersions := func(versions ...uint16) []uint16 {
		if browserType == chrome {
			return append([]uint16{utls.GREASE_PLACEHOLDER}, versions...)
		}
		return versions
	}

	switch ver {
	case utls.VersionTLS13 - 1:
		tlsMaxVersion = utls.VersionTLS13
		tlsMinVersion = utls.VersionTLS12
		tlsSupport = &utls.SupportedVersionsExtension{
			Versions: buildVersions(utls.VersionTLS13, utls.VersionTLS12),
		}
	case utls.VersionTLS12 - 1:
		tlsMaxVersion = utls.VersionTLS12
		tlsMinVersion = utls.VersionTLS11
		tlsSupport = &utls.SupportedVersionsExtension{
			Versions: buildVersions(utls.VersionTLS12, utls.VersionTLS11),
		}
	case utls.VersionTLS11 - 1:
		tlsMaxVersion = utls.VersionTLS11
		tlsMinVersion = utls.VersionTLS10
		tlsSupport = &utls.SupportedVersionsExtension{
			Versions: buildVersions(utls.VersionTLS11, utls.VersionTLS10),
		}
	default:
		err = errors.New("ja3Str tls version error")
	}
	return
}

func PrettyStruct(data interface{}) (string, error) {
	val, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return "", err
	}
	return string(val), nil
}

// ConvertUtlsConfig 将 utls.Config 转换为 tls.Config
func ConvertUtlsConfig(utlsConfig *utls.Config) *tls.Config {
	if utlsConfig == nil {
		return nil
	}

	return &tls.Config{
		Rand:               utlsConfig.Rand,
		Time:               utlsConfig.Time,
		RootCAs:            utlsConfig.RootCAs,
		NextProtos:         utlsConfig.NextProtos,
		ServerName:         utlsConfig.ServerName,
		InsecureSkipVerify: utlsConfig.InsecureSkipVerify,
		CipherSuites:       utlsConfig.CipherSuites,
		MinVersion:         utlsConfig.MinVersion,
		MaxVersion:         utlsConfig.MaxVersion,
	}
}
