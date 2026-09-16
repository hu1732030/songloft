package handlers

import "fmt"

// userScopedConfigKey 将配置键按用户隔离；userID<=0 时回退全局键（兼容旧数据/测试）。
func userScopedConfigKey(base string, userID int64) string {
	if userID <= 0 {
		return base
	}
	return fmt.Sprintf("%s:u%d", base, userID)
}
