package winfs

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func fixedDrives() ([]string, error) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, fmt.Errorf("listing Windows drives: %w", err)
	}
	var drives []string
	for i := 0; i < 26; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		path, err := windows.UTF16PtrFromString(root)
		if err != nil {
			return nil, fmt.Errorf("encoding drive %s: %w", root, err)
		}
		if windows.GetDriveType(path) == windows.DRIVE_FIXED {
			drives = append(drives, root)
		}
	}
	return drives, nil
}
