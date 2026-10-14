package api

import (
	"fmt"
	"time"
)

type HealingLimits struct {
	MaxAttemptsPerIncident int `json:"maxAttemptsPerIncident"`
	RetryCooldownSeconds   int `json:"retryCooldownSeconds"`
	WindowSeconds          int `json:"windowSeconds"`
	MaxModelCallsPerWindow int `json:"maxModelCallsPerWindow"`
	MaxToolCallsPerWindow  int `json:"maxToolCallsPerWindow"`
}
type BudgetStatus struct {
	WindowStartedAt time.Time `json:"windowStartedAt"`
	ModelCalls      int       `json:"modelCalls"`
	ToolCalls       int       `json:"toolCalls"`
}

func DefaultHealingLimits() HealingLimits { return HealingLimits{3, 30, 3600, 20, 100} }
func (l HealingLimits) Validate() error {
	if l.MaxAttemptsPerIncident < 1 || l.MaxAttemptsPerIncident > 10 || l.RetryCooldownSeconds < 5 || l.RetryCooldownSeconds > 3600 || l.WindowSeconds < 60 || l.WindowSeconds > 86400 || l.MaxModelCallsPerWindow < 1 || l.MaxModelCallsPerWindow > 1000 || l.MaxToolCallsPerWindow < 1 || l.MaxToolCallsPerWindow > 10000 {
		return fmt.Errorf("healing limits outside bounds")
	}
	return nil
}
func TaskHealingLimits(t TaskSpec) HealingLimits {
	if t.HealingLimits != nil {
		return *t.HealingLimits
	}
	return DefaultHealingLimits()
}
