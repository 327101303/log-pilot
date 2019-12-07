package pilot

import (
	"fmt"
	"os"
)

// Global variables for piloter
const (
	ENV_PILOT_TYPE = "PILOT_TYPE"

	PILOT_FILEBEAT = "filebeat"
	PILOT_FLUENTD  = "fluentd"
)

// Piloter interface for piloter
type Piloter interface {
	Name() string

	Start() error
	Reload() error
	Stop() error

	GetBaseConf() string
	GetConfHome() string
	GetConfPath(container string) string

	OnDestroyEvent(container string) error
}

// NewPiloter instantiates a new piloter
// 通过basedir实例一个piloter，获取env，判断backprocess是filebeat或fluentd
func NewPiloter(baseDir string) (Piloter, error) {
	if os.Getenv(ENV_PILOT_TYPE) == PILOT_FILEBEAT {
		return NewFilebeatPiloter(baseDir)
	}
	if os.Getenv(ENV_PILOT_TYPE) == PILOT_FLUENTD {
		return NewFluentdPiloter()
	}
	return nil, fmt.Errorf("InvalidPilotType")
}
