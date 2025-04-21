package internal

import (
	"fmt"
)

// DataError indicates that this error is caused by invalid data, so retrying
// this request will not make any difference. This is used by the poller to hint
// at whether or not we should advance the since token on error.
type DataError struct {
	msg string
}

func (e *DataError) Error() string {
	return e.msg
}

func NewDataError(msg string, args ...interface{}) error {
	return &DataError{
		msg: fmt.Sprintf("DataError: "+msg, args...),
	}
}
