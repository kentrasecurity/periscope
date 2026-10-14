package controller

import (
	"fmt"
	"github.com/kentrasecurity/periscope/internal/api"
	"github.com/kentrasecurity/periscope/internal/kube"
	"time"
)

func ReserveBudget(status api.BudgetStatus, limits api.HealingLimits, now time.Time, modelCalls, toolCalls int) (api.BudgetStatus, error) {
	if err := limits.Validate(); err != nil {
		return status, err
	}
	if modelCalls < 0 || toolCalls < 0 {
		return status, fmt.Errorf("negative reservation")
	}
	if status.WindowStartedAt.IsZero() || !now.Before(status.WindowStartedAt.Add(time.Duration(limits.WindowSeconds)*time.Second)) {
		status = api.BudgetStatus{WindowStartedAt: now}
	}
	if status.ModelCalls+modelCalls > limits.MaxModelCallsPerWindow || status.ToolCalls+toolCalls > limits.MaxToolCallsPerWindow {
		return status, fmt.Errorf("rolling inference budget exhausted; observations continue")
	}
	status.ModelCalls += modelCalls
	status.ToolCalls += toolCalls
	return status, nil
}

// rolling reports whether a task is bounded by a rolling inference window.
// Continuously monitoring tasks (scopes, explicit limits, Observe) always are.
func rolling(t *kube.Task) bool {
	return t.Spec.Scope != nil || t.Spec.HealingLimits != nil || t.Spec.Mode == "Observe"
}
func reserveTask(t *kube.Task, model, tool int) error {
	if !rolling(t) {
		return nil
	}
	status, err := ReserveBudget(t.Status.Budget, api.TaskHealingLimits(t.Spec), time.Now().UTC(), model, tool)
	if err != nil {
		return err
	}
	t.Status.Budget = status
	return nil
}
func renewWindow(t *kube.Task) bool {
	if !rolling(t) {
		return false
	}
	status, err := ReserveBudget(t.Status.Budget, api.TaskHealingLimits(t.Spec), time.Now().UTC(), 0, 0)
	if err != nil {
		return false
	}
	renewed := !status.WindowStartedAt.Equal(t.Status.Budget.WindowStartedAt)
	t.Status.Budget = status
	if renewed {
		t.Status.ModelCalls = 0
		t.Status.ToolCalls = 0
	}
	return renewed
}
