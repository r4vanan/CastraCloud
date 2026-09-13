package api

import (
	"net/http"

	"github.com/castracloud/castracloud/internal/compliance"
	"github.com/google/uuid"
)

func (s *Server) handleListFrameworks(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	if err := compliance.Seed(r.Context(), s.db, tenant); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	frameworks, err := s.db.ListFrameworks(r.Context(), tenant)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, frameworks)
}

func (s *Server) handleListControls(w http.ResponseWriter, r *http.Request) {
	frameworkID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	controls, err := s.db.ListControls(r.Context(), frameworkID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, controls)
}
