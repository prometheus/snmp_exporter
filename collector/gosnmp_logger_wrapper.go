package collector

import (
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

type gosnmpLogger struct {
	log.Logger
}

func (l *gosnmpLogger) Print(v ...interface{}) {
	level.Debug(l).Log("module", "gosnmp", "msg", fmt.Sprintf("%v", v))
}

func (l *gosnmpLogger) Printf(format string, v ...interface{}) {
	level.Debug(l).Log("module", "gosnmp", "msg", fmt.Sprintf(format, v))
}
