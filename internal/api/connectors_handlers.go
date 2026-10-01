package api

import (
	"encoding/json"
	"net/http"

	"github.com/castracloud/castracloud/internal/config"
	credentialcrypto "github.com/castracloud/castracloud/internal/crypto"
	"github.com/castracloud/castracloud/internal/store"
	"github.com/google/uuid"
)

func (s *Server) handleListConnectors(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	if s.db == nil {
		s.writeError(w, http.StatusServiceUnavailable, nil)
		return
	}
	list, err := s.db.ListConnectors(r.Context(), tenant)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCreateConnector(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	var body struct {
		Name        string         `json:"name"`
		Provider    string         `json:"provider"`
		Region      string         `json:"region"`
		Credentials map[string]any `json:"credentials"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Name == "" || body.Provider == "" {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}
	if body.Provider != "aws" && body.Provider != "gcp" && body.Provider != "azure" {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}
	if body.Region == "" {
		body.Region = "us-east-1"
	}
	conn := &store.CloudConnector{
		TenantID: tenant,
		Name:     body.Name,
		Provider: body.Provider,
		Region:   body.Region,
		Status:   "configured",
	}
	if len(body.Credentials) > 0 {
		raw, err := json.Marshal(body.Credentials)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err)
			return
		}
		key := config.Env("CREDENTIAL_ENCRYPTION_KEY", "")
		if key == "" {
			s.writeError(w, http.StatusServiceUnavailable, nil)
			return
		}
		conn.CredentialsEncrypted, err = credentialcrypto.Encrypt(key, string(raw))
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if s.db == nil {
		s.writeError(w, http.StatusServiceUnavailable, nil)
		return
	}
	if err := s.db.CreateConnector(r.Context(), conn); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.audit(r.Context(), "connector.create", conn.Name, map[string]any{"provider": conn.Provider})
	s.writeJSON(w, http.StatusCreated, conn)
}

func (s *Server) handleDeleteConnector(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if s.db != nil {
		if err := s.db.DeleteConnector(r.Context(), tenant, id); err != nil {
			if err == store.ErrNotFound {
				s.writeError(w, http.StatusNotFound, err)
				return
			}
			s.writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	s.audit(r.Context(), "connector.delete", id.String(), map[string]any{})
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleScanConnector(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	if s.db == nil {
		s.writeError(w, http.StatusServiceUnavailable, nil)
		return
	}
	connConfig, err := s.db.GetConnector(r.Context(), tenant, id)
	if err == store.ErrNotFound {
		s.writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	scanned, ingested, err := s.runScan(r.Context(), tenant, connConfig)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.audit(r.Context(), "connector.scan", connConfig.Name, map[string]any{"findings": scanned})
	s.writeJSON(w, http.StatusOK, map[string]any{
		"provider": connConfig.Provider,
		"scanned":  scanned,
		"ingested": ingested,
	})
}
