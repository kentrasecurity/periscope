package api

import "testing"

func TestValidateTask(t *testing.T) {
	valid := TaskSpec{TargetRef: TargetRef{APIVersion: "apps/v1", Kind: "Deployment", Name: "api"}, Mode: "HumanApproved", Objective: "fix", Limits: DefaultLimits()}
	if err := ValidateTask(valid); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"", "root"} {
		v := valid
		v.Mode = mode
		if ValidateTask(v) == nil {
			t.Fatalf("unexpected mode accepted: %s", mode)
		}
	}
	v := valid
	v.Limits.MaxModelCalls = 1000
	if ValidateTask(v) == nil {
		t.Fatal("excessive model calls accepted")
	}
	v = valid
	v.Objective = ""
	if ValidateTask(v) == nil {
		t.Fatal("missing objective accepted")
	}
}

func TestGracePeriodBoundsAndDefault(t *testing.T) {
	valid := TaskSpec{TargetRef: TargetRef{APIVersion: "apps/v1", Kind: "Deployment", Name: "api"}, Mode: "Observe", Objective: "watch", Limits: DefaultLimits()}
	if valid.GracePeriod().Seconds() != DefaultGracePeriodSeconds {
		t.Fatal("unexpected default grace period")
	}
	for seconds, ok := range map[int]bool{0: true, 3600: true, -1: false, 3601: false} {
		v := valid
		s := seconds
		v.Monitoring = &Monitoring{IntervalSeconds: 30, GracePeriodSeconds: &s}
		if err := ValidateTask(v); (err == nil) != ok {
			t.Fatalf("grace %d: validation error %v", seconds, err)
		}
	}
}

func TestAppendConditionsKeepsNewest(t *testing.T) {
	conditions := []Condition{}
	for n := 0; n < 100; n++ {
		conditions = AppendConditions(conditions, Condition{Type: "RemediationVerified", Reason: string(rune('a' + n%26))})
	}
	if len(conditions) != MaxConditions || conditions[len(conditions)-1].Reason != string(rune('a'+99%26)) {
		t.Fatalf("conditions unbounded or newest dropped: %d", len(conditions))
	}
}
