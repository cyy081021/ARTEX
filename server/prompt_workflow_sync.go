package server

import (
	"log"

	"github.com/Autumn-27/artex/agent"
)

func (s *Server) syncReporterPrompt() {
	a, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil {
		log.Printf("[reporter] read prompt owner: %v", err)
		return
	}
	if a == nil {
		return // A deliberately deleted optional agent must stay deleted.
	}
	if _, err := s.m.pg.SyncBuiltinPrompt(a.ID, agent.ReporterDefaultPrompt, agent.LegacyBuiltinPromptHashes("reporter")); err != nil {
		log.Printf("[reporter] sync known default failed, will retry on restart: %v", err)
	}
}

func (s *Server) syncRetryToolDescription() {
	_, err := s.m.pg.Exec(`UPDATE tools SET description=$1 WHERE system AND key IN ('retry_intent','reverse__retry_intent') AND description=$2`, agent.RetryIntentDescription, agent.LegacyRetryIntentDescription)
	if err != nil {
		log.Printf("[tools] sync known retry description failed, will retry on restart: %v", err)
	}
}
