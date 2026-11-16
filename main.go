package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

type app struct {
	db      *sql.DB
	token   string
	hmacKey []byte
	tmpl    *template.Template
	limit   *limiter
}

func main() {
	adminPass := os.Getenv("ADMIN_PASSWORD")
	token := os.Getenv("EA_API_TOKEN")
	if adminPass == "" || token == "" {
		log.Fatal("ADMIN_PASSWORD dan EA_API_TOKEN wajib diisi")
	}
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		dir = "data"
	}
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	db, err := openDB(dir)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := ensureAdminHash(db, adminPass); err != nil {
		log.Fatal(err)
	}
	key, err := loadHMACKey(dir)
	if err != nil {
		log.Fatal(err)
	}

	s := &app{
		db:      db,
		token:   token,
		hmacKey: key,
		tmpl:    template.Must(template.ParseFS(templateFS, "templates/*.html")),
		limit:   newLimiter(30, time.Minute),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.home)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /admin", s.adminPage)
	mux.HandleFunc("POST /admin/licenses", s.addLicense)
	mux.HandleFunc("POST /admin/licenses/extend", s.extendLicense)
	mux.HandleFunc("POST /admin/licenses/disable", s.disableLicense)
	mux.HandleFunc("POST /admin/licenses/enable", s.enableLicense)
	mux.HandleFunc("POST /api/ea_get_mode", s.eaMode)

	log.Printf("lisensi mendengarkan %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func loadHMACKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "session.key")
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*hit
}

type hit struct {
	start time.Time
	n     int
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, hits: map[string]*hit{}}
}

func (l *limiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	h := l.hits[ip]
	if h == nil || now.Sub(h.start) >= l.window {
		l.hits[ip] = &hit{start: now, n: 1}
		return true
	}
	if h.n >= l.max {
		return false
	}
	h.n++
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *app) sign(payload string) string {
	mac := hmac.New(sha256.New, s.hmacKey)
	_, _ = mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

func (s *app) openSession(raw string) (csrf string, ok bool) {
	payload, sig, found := strings.Cut(raw, ".")
	if !found {
		return "", false
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, s.hmacKey)
	_, _ = mac.Write([]byte(payload))
	if !hmac.Equal(got, mac.Sum(nil)) {
		return "", false
	}
	expText, csrf, found := strings.Cut(payload, "|")
	if !found || csrf == "" {
		return "", false
	}
	exp, err := strconv.ParseInt(expText, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	return csrf, true
}

func (s *app) setSession(w http.ResponseWriter, r *http.Request) string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	csrf := hex.EncodeToString(buf)
	exp := time.Now().Add(12 * time.Hour).Unix()
	http.SetCookie(w, &http.Cookie{
		Name:     "lic_session",
		Value:    s.sign(strconv.FormatInt(exp, 10) + "|" + csrf),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		MaxAge:   12 * 3600,
	})
	return csrf
}

func (s *app) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "lic_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

func (s *app) sessionCSRF(r *http.Request) (string, bool) {
	c, err := r.Cookie("lic_session")
	if err != nil {
		return "", false
	}
	return s.openSession(c.Value)
}

func (s *app) requireAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	csrf, ok := s.sessionCSRF(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return "", false
	}
	return csrf, true
}

func (s *app) checkCSRF(r *http.Request, csrf string) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Form.Get("csrf")), []byte(csrf)) == 1
}

func (s *app) home(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sessionCSRF(r); ok {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", map[string]any{"Error": ""})
}

func (s *app) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak valid", http.StatusBadRequest)
		return
	}
	if !checkAdminPassword(s.db, r.Form.Get("password")) {
		s.render(w, "login.html", map[string]any{"Error": "Kata sandi salah."})
		return
	}
	s.setSession(w, r)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *app) logout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func messageOf(code string) string {
	switch code {
	case "saved":
		return "Akun tersimpan."
	case "extended":
		return "Tanggal diperpanjang."
	case "disabled":
		return "Lisensi dimatikan."
	case "enabled":
		return "Lisensi diaktifkan."
	default:
		return ""
	}
}

func (s *app) adminPage(w http.ResponseWriter, r *http.Request) {
	csrf, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	rows, err := listLicenses(s.db)
	if err != nil {
		http.Error(w, "gagal membaca data", http.StatusInternalServerError)
		return
	}
	s.render(w, "admin.html", map[string]any{
		"CSRF":     csrf,
		"Licenses": rows,
		"Today":    time.Now().UTC().Format("2006-01-02"),
		"Message":  messageOf(r.URL.Query().Get("msg")),
	})
}

func parseAccount(v string) (int64, bool) {
	if v == "" || len(v) > 18 {
		return 0, false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func parseDate(v string) (string, bool) {
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return "", false
	}
	return t.Format("2006-01-02"), true
}

func (s *app) addLicense(w http.ResponseWriter, r *http.Request) {
	csrf, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.checkCSRF(r, csrf) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	account, okAcc := parseAccount(r.Form.Get("account"))
	expires, okDate := parseDate(r.Form.Get("expires"))
	product := r.Form.Get("product")
	if !okAcc || !okDate {
		http.Error(w, "akun atau tanggal tidak valid", http.StatusBadRequest)
		return
	}
	note := strings.TrimSpace(r.Form.Get("note"))
	if len(note) > 200 {
		note = note[:200]
	}
	products := []string{product}
	if product == "both" {
		products = []string{"btcusd", "xau"}
	}
	if product != "btcusd" && product != "xau" && product != "both" {
		http.Error(w, "produk tidak dikenal", http.StatusBadRequest)
		return
	}
	for _, p := range products {
		if err := upsertLicense(s.db, account, p, expires, note); err != nil {
			http.Error(w, "gagal menyimpan", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/admin?msg=saved", http.StatusSeeOther)
}

func formID(r *http.Request) (int64, bool) {
	return parseAccount(r.Form.Get("id"))
}

func (s *app) extendLicense(w http.ResponseWriter, r *http.Request) {
	csrf, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.checkCSRF(r, csrf) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	id, okID := formID(r)
	expires, okDate := parseDate(r.Form.Get("expires"))
	if !okID || !okDate || setExpiry(s.db, id, expires) != nil {
		http.Error(w, "gagal memperpanjang", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin?msg=extended", http.StatusSeeOther)
}

func (s *app) disableLicense(w http.ResponseWriter, r *http.Request) {
	s.setLicenseActive(w, r, false, "disabled")
}

func (s *app) enableLicense(w http.ResponseWriter, r *http.Request) {
	s.setLicenseActive(w, r, true, "enabled")
}

func (s *app) setLicenseActive(w http.ResponseWriter, r *http.Request, active bool, msg string) {
	csrf, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.checkCSRF(r, csrf) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	id, okID := formID(r)
	if !okID || setActive(s.db, id, active) != nil {
		http.Error(w, "gagal mengubah status", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin?msg="+msg, http.StatusSeeOther)
}

type eaRequest struct {
	Account json.Number `json:"account"`
	Server  string      `json:"server"`
	Product string      `json:"product"`
	Pass    string      `json:"pass"`
}

func (s *app) eaMode(w http.ResponseWriter, r *http.Request) {
	if !s.limit.allow(clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "Terlalu banyak permintaan"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Kesalahan Credentials"})
		return
	}
	var req eaRequest
	if json.Unmarshal(body, &req) != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Kesalahan Credentials"})
		return
	}
	passOK := len(req.Pass) == len(s.token) &&
		subtle.ConstantTimeCompare([]byte(req.Pass), []byte(s.token)) == 1
	if !passOK {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Kesalahan Credentials"})
		return
	}
	if req.Product != "btcusd" && req.Product != "xau" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Akun tidak terdaftar"})
		return
	}
	account, err := req.Account.Int64()
	if err != nil || account <= 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Akun tidak terdaftar"})
		return
	}
	server := strings.TrimSpace(req.Server)
	if len(server) > 120 {
		server = server[:120]
	}
	status, expires, err := licenseStatus(s.db, account, req.Product, server)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Server lisensi bermasalah"})
		return
	}
	switch status {
	case "ok":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": "run", "expires": expires})
	case "expired":
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Masa sewa EA telah berakhir"})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Akun tidak terdaftar"})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func (s *app) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}
