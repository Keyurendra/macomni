package winfs

import "errors"

func fixedDrives() ([]string, error) {
	return nil, errors.New("live Windows filesystem scanning requires Windows")
}
