package api

import (
	"net/http"

	"github.com/castracloud/castracloud/internal/attack"
)

// handleAttackPath computes and returns the tenant's attack-path graph.
func (s *Server) handleAttackPath(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())

	assets, err := s.db.ListAssets(r.Context(), tenant)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	findings, err := s.db.ListFindings(r.Context(), tenant, "", "open", 5000)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.writeJSON(w, http.StatusOK, attack.Analyze(assets, findings))
}
