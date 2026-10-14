package evidence

import "time"

type Query struct {
	Namespace, Application, Version string
	Now                             time.Time
}
type Runbook struct {
	ID          string    `json:"id"`
	Namespace   string    `json:"namespace"`
	Application string    `json:"application"`
	Version     string    `json:"version"`
	Revision    string    `json:"revision"`
	Text        string    `json:"text"`
	Reviewed    bool      `json:"reviewed"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

func Retrieve(books []Runbook, q Query) []Runbook {
	var result []Runbook
	for _, b := range books {
		if b.Reviewed && b.Namespace == q.Namespace && b.Application == q.Application && b.Version == q.Version && b.ExpiresAt.After(q.Now) {
			b.Text = Bound(Redact(b.Text), 8192)
			result = append(result, b)
			if len(result) == 8 {
				break
			}
		}
	}
	return result
}
