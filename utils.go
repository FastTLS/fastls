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
	"io"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	utls "github.com/refraction-networking/utls"
)

const (
	chrome  = "chrome"  //chrome User agent enum
	firefox = "firefox" //firefox User agent enum
)

func parseUserAgent(userAgent string) string {
	switch {
	case strings.Contains(strings.ToLower(userAgent), "firefox"):
		return firefox
	default:
		return chrome
	}
}

// DecompressBody unzips compressed data
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

// StringToSpec creates a ClientHelloSpec based on a JA3 or JA4R string
// 如果是指纹类型为 "ja4r"，则返回错误（JA4R 需要不同的处理方式）
func StringToSpec(fingerprint string, userAgent string) (*utls.ClientHelloSpec, error) {
	// 检查是否是 JA4R 格式（JA4R 格式：t13d<num>_<cipher_suites>_<extensions>_<signature_algorithms>）
	// 例如：t13d5911_002f,0032,..._000a,000b,..._0403,0503,...
	if strings.HasPrefix(fingerprint, "t") && strings.Count(fingerprint, "_") >= 3 {
		// 尝试解析 JA4R 格式
		return ParseJA4R(fingerprint, userAgent)
	}
	// 继续处理 JA3 格式
	ja3 := fingerprint
	browserType := parseUserAgent(userAgent)
	tokens := strings.Split(ja3, ",")

	version := tokens[0]
	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")

	// 检查 JA3 字符串中是否包含 PSK 扩展（扩展ID 41）
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
	// parse curves
	var targetCurves []utls.CurveID
	if browserType == chrome {
		targetCurves = append(
			targetCurves,
			utls.CurveID(utls.GREASE_PLACEHOLDER),
			//utls.X25519MLKEM768,
		) //append grease for Chrome browsers
	}

	for _, c := range curves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		targetCurves = append(targetCurves, utls.CurveID(cid))
	}

	extMap["10"] = &utls.SupportedCurvesExtension{Curves: targetCurves}

	// parse point formats
	var targetPointFormats []byte
	for _, p := range pointFormats {
		pid, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, err
		}
		targetPointFormats = append(targetPointFormats, byte(pid))
	}
	extMap["11"] = &utls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	// set extension 43
	ver, err := strconv.ParseUint(version, 10, 16)
	if err != nil {
		return nil, err
	}
	tlsMaxVersion, tlsMinVersion, tlsExtension, err := createTlsVersion(uint16(ver), browserType)
	if err != nil {
		return nil, err
	}
	extMap["43"] = tlsExtension

	// build extenions list
	// PSK扩展（41）必须是最后一个扩展，需要特殊处理
	var exts []utls.TLSExtension
	var pskExt utls.TLSExtension

	//Optionally Add Chrome Grease Extension
	if browserType == chrome {
		exts = append(exts, &utls.UtlsGREASEExtension{
			Body: []byte{},
		})
	}

	// 先添加所有非PSK扩展，PSK扩展单独处理
	for _, e := range extensions {
		if e == "41" {
			// PSK扩展需要放在最后，先保存起来
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

	// Chrome的最后一个GREASE扩展应该在PSK之前（如果PSK存在）
	// 如果PSK不存在，GREASE在最后
	if browserType == chrome && pskExt != nil {
		exts = append(exts, &utls.UtlsGREASEExtension{
			Body: []byte{},
		})
	}

	// PSK扩展必须是最后一个扩展
	if pskExt != nil {
		exts = append(exts, pskExt)
	}

	// build CipherSuites
	var suites []uint16
	//Optionally Add Chrome Grease Extension
	// if browserType == chrome && !tlsExtensions.UseGREASE {
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

// TLSVersion，Ciphers，Extensions，EllipticCurves，EllipticCurvePointFormats
func createTlsVersion(ver uint16, browserType string) (tlsMaxVersion uint16, tlsMinVersion uint16, tlsSupport utls.TLSExtension, err error) {
	// Helper function 根据 UA 是否是 chrome 来构建 Versions 列表
	buildVersions := func(versions ...uint16) []uint16 {
		if browserType == "chrome" {
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

// ConvertUtlsConfig converts utls.Config to tls.Config
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
