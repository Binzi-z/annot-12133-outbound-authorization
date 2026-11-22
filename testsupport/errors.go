package testsupport

import "errors"

var errWaitTimeout = errors.New("testsupport: timed out waiting for policy version")
