package admission

import (
	"encoding/json"
	"io"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
)

func (v *Validator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 {
		http.Error(w, "invalid or oversized admission body", http.StatusBadRequest)
		return
	}
	var review admissionv1.AdmissionReview
	if e = json.Unmarshal(raw, &review); e != nil || review.Request == nil {
		http.Error(w, "invalid admission review", http.StatusBadRequest)
		return
	}
	response := v.Validate(r.Context(), review)
	result := admissionv1.AdmissionReview{TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"}, Response: &response}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
