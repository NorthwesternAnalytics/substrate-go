package trust

import (
	"encoding/json"
	"net/http"
)

// writeJSON is the module's own minimal response writer, used only by the
// default RefusalWriter. An adopting app supplies its own writer and this is
// never reached — it exists so the module is usable before an app has one.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
