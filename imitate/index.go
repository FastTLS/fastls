package imitate

import (
	"math/rand"
	"strings"
)

func shuffleExtension(extension string, l21 int) string {
	// l21 为21的位置
	extensions := strings.Split(extension, "-")
	// 随机判断删除值为21的元素
	if rand.Intn(2) == 1 && l21 >= 0 {
		extensions = append(extensions[:l21], extensions[l21+1:]...)
	}
	// 随机打乱
	for i := range extensions {
		j := rand.Intn(len(extensions))
		extensions[i], extensions[j] = extensions[j], extensions[i]
	}
	return strings.Join(extensions, "-")
}
