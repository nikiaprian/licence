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
	"errors"
	"html/template"
	"io"
	"log"
	"math"
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
	db         *sql.DB
	token      string
	hmacKey    []byte
	tmpl       *template.Template
	limit      *limiter
	loginLimit *limiter
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
		db:         db,
		token:      token,
		hmacKey:    key,
		tmpl:       template.Must(template.ParseFS(templateFS, "templates/*.html")),
		limit:      newLimiter(30, time.Minute),
		loginLimit: newLimiter(10, time.Minute),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.home)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /user", s.userPage)
	mux.HandleFunc("POST /user/licenses", s.addLicense)
	mux.HandleFunc("POST /user/licenses/extend", s.extendLicense)
	mux.HandleFunc("POST /user/licenses/disable", s.disableLicense)
	mux.HandleFunc("POST /user/licenses/enable", s.enableLicense)
	mux.HandleFunc("POST /user/stop-impersonate", s.stopImpersonate)
	mux.HandleFunc("GET /admin", s.adminPage)
	mux.HandleFunc("POST /admin/users", s.createUser)
	mux.HandleFunc("POST /admin/users/password", s.changePassword)
	mux.HandleFunc("POST /admin/users/can-add", s.setCanAdd)
	mux.HandleFunc("POST /admin/users/delete", s.removeUser)
	mux.HandleFunc("POST /admin/impersonate", s.impersonate)
	mux.HandleFunc("POST /admin/licenses/assign", s.assignLicense)
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

type session struct {
	CSRF          string
	Role          string
	UserID        int64
	Impersonating bool
}

func (s *app) openSession(raw string) (session, bool) {
	payload, sig, found := strings.Cut(raw, ".")
	if !found {
		return session{}, false
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		return session{}, false
	}
	mac := hmac.New(sha256.New, s.hmacKey)
	_, _ = mac.Write([]byte(payload))
	if !hmac.Equal(got, mac.Sum(nil)) {
		return session{}, false
	}
	parts := strings.Split(payload, "|")
	if len(parts) != 5 || parts[1] == "" {
		return session{}, false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return session{}, false
	}
	uid, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return session{}, false
	}
	role, imp := parts[2], parts[4]
	sess := session{CSRF: parts[1], Role: role, UserID: uid, Impersonating: imp == "1"}
	switch role {
	case "admin":
		if uid != 0 || imp != "0" {
			return session{}, false
		}
	case "user":
		if uid <= 0 || (imp != "0" && imp != "1") {
			return session{}, false
		}
	default:
		return session{}, false
	}
	return sess, true
}

func (s *app) setSession(w http.ResponseWriter, r *http.Request, role string, userID int64, impersonating bool) string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	csrf := hex.EncodeToString(buf)
	exp := time.Now().Add(12 * time.Hour).Unix()
	imp := "0"
	if impersonating {
		imp = "1"
	}
	payload := strconv.FormatInt(exp, 10) + "|" + csrf + "|" + role + "|" + strconv.FormatInt(userID, 10) + "|" + imp
	http.SetCookie(w, &http.Cookie{
		Name:     "lic_session",
		Value:    s.sign(payload),
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

func (s *app) currentSession(r *http.Request) (session, bool) {
	c, err := r.Cookie("lic_session")
	if err != nil {
		return session{}, false
	}
	return s.openSession(c.Value)
}

func (s *app) requireAdmin(w http.ResponseWriter, r *http.Request) (session, bool) {
	sess, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return session{}, false
	}
	if sess.Role != "admin" {
		http.Redirect(w, r, "/user", http.StatusSeeOther)
		return session{}, false
	}
	return sess, true
}

func (s *app) requireUser(w http.ResponseWriter, r *http.Request) (session, bool) {
	sess, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return session{}, false
	}
	if sess.Role != "user" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return session{}, false
	}
	if _, err := userByID(s.db, sess.UserID); err != nil {
		s.clearSession(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return session{}, false
	}
	return sess, true
}

func (s *app) checkCSRF(r *http.Request, csrf string) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Form.Get("csrf")), []byte(csrf)) == 1
}

func (s *app) home(w http.ResponseWriter, r *http.Request) {
	if sess, ok := s.currentSession(r); ok {
		if sess.Role == "admin" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/user", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", map[string]any{"Error": ""})
}

func (s *app) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "permintaan tidak valid", http.StatusBadRequest)
		return
	}
	if !s.loginLimit.allow(clientIP(r)) {
		s.render(w, "login.html", map[string]any{"Error": "Terlalu banyak percobaan. Coba lagi sebentar."})
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.Form.Get("username")))
	pass := r.Form.Get("password")
	if name == "admin" {
		if checkAdminPassword(s.db, pass) {
			s.setSession(w, r, "admin", 0, false)
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		s.render(w, "login.html", map[string]any{"Error": "Username atau kata sandi salah."})
		return
	}
	username, okName := parseUsername(name)
	var id int64
	okPass := false
	if okName {
		id, okPass = checkUserPassword(s.db, username, pass)
	}
	if !okPass {
		s.render(w, "login.html", map[string]any{"Error": "Username atau kata sandi salah."})
		return
	}
	s.setSession(w, r, "user", id, false)
	http.Redirect(w, r, "/user", http.StatusSeeOther)
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
	case "taken":
		return "Nomor akun itu sudah terdaftar pada user lain."
	case "user-created":
		return "User dibuat."
	case "user-exists":
		return "Username itu sudah dipakai."
	case "user-deleted":
		return "User dan lisensinya dihapus."
	case "password":
		return "Kata sandi diubah."
	case "assigned":
		return "Lisensi dipindahkan ke user."
	case "bad-user":
		return "Username 3–32 huruf, angka, atau garis bawah. Kata sandi minimal 6 karakter."
	case "can-add":
		return "User ini sekarang boleh menambah akun sendiri."
	case "can-add-off":
		return "User ini tidak lagi boleh menambah akun."
	case "forbidden":
		return "Penambahan akun hanya bisa dilakukan admin."
	case "no-extend":
		return "Tanggal perpanjang hanya bisa diubah admin."
	default:
		return ""
	}
}

func (s *app) userPage(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	rows, err := listLicenses(s.db, sess.UserID)
	if err != nil {
		http.Error(w, "gagal membaca data", http.StatusInternalServerError)
		return
	}
	profitDay, _ := parseDate(r.URL.Query().Get("day"))
	if err := applyProfitDay(s.db, profitDay, rows); err != nil {
		http.Error(w, "gagal membaca data", http.StatusInternalServerError)
		return
	}
	user, err := userByID(s.db, sess.UserID)
	if err != nil {
		http.Error(w, "gagal membaca data", http.StatusInternalServerError)
		return
	}
	s.render(w, "user.html", map[string]any{
		"CSRF":          sess.CSRF,
		"Licenses":      rows,
		"Today":         time.Now().UTC().Format("2006-01-02"),
		"Message":       messageOf(r.URL.Query().Get("msg")),
		"Username":      user.Username,
		"Impersonating": sess.Impersonating,
		"CanAdd":        sess.Impersonating || user.CanAdd,
		"ProfitDay":     profitDay,
	})
}

func (s *app) adminPage(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	users, loose, err := listUsersAndLicenses(s.db)
	if err != nil {
		http.Error(w, "gagal membaca data", http.StatusInternalServerError)
		return
	}
	profitDay, _ := parseDate(r.URL.Query().Get("day"))
	lists := make([][]License, 0, len(users)+1)
	for i := range users {
		lists = append(lists, users[i].Licenses)
	}
	lists = append(lists, loose)
	if err := applyProfitDay(s.db, profitDay, lists...); err != nil {
		http.Error(w, "gagal membaca data", http.StatusInternalServerError)
		return
	}
	openID, _ := strconv.ParseInt(r.URL.Query().Get("open"), 10, 64)
	s.render(w, "admin.html", map[string]any{
		"CSRF":       sess.CSRF,
		"Users":      users,
		"Unassigned": loose,
		"Message":    messageOf(r.URL.Query().Get("msg")),
		"Open":       openID,
		"ProfitDay":  profitDay,
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

func parseUsername(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if len(v) < 3 || len(v) > 32 || v == "admin" {
		return "", false
	}
	for _, c := range v {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return "", false
		}
	}
	return v, true
}

func validPassword(p string) bool {
	return len(p) >= 6 && len(p) <= 72
}

func (s *app) addLicense(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if !s.checkCSRF(r, sess.CSRF) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	if !sess.Impersonating {
		user, err := userByID(s.db, sess.UserID)
		if err != nil || !user.CanAdd {
			http.Redirect(w, r, "/user?msg=forbidden", http.StatusSeeOther)
			return
		}
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
		if err := saveLicense(s.db, sess.UserID, account, p, expires, note); err != nil {
			if errors.Is(err, errLicenseTaken) {
				http.Redirect(w, r, "/user?msg=taken", http.StatusSeeOther)
				return
			}
			http.Error(w, "gagal menyimpan", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/user?msg=saved", http.StatusSeeOther)
}

func formID(r *http.Request) (int64, bool) {
	return parseAccount(r.Form.Get("id"))
}

func (s *app) extendLicense(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if !s.checkCSRF(r, sess.CSRF) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	if !sess.Impersonating {
		user, err := userByID(s.db, sess.UserID)
		if err != nil || !user.CanAdd {
			http.Redirect(w, r, "/user?msg=no-extend", http.StatusSeeOther)
			return
		}
	}
	id, okID := formID(r)
	expires, okDate := parseDate(r.Form.Get("expires"))
	if !okID || !okDate || setExpiry(s.db, id, sess.UserID, expires) != nil {
		http.Error(w, "gagal memperpanjang", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/user?msg=extended", http.StatusSeeOther)
}

func (s *app) disableLicense(w http.ResponseWriter, r *http.Request) {
	s.setLicenseActive(w, r, false, "disabled")
}

func (s *app) enableLicense(w http.ResponseWriter, r *http.Request) {
	s.setLicenseActive(w, r, true, "enabled")
}

func (s *app) setLicenseActive(w http.ResponseWriter, r *http.Request, active bool, msg string) {
	sess, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if !s.checkCSRF(r, sess.CSRF) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	id, okID := formID(r)
	if !okID || setActive(s.db, id, sess.UserID, active) != nil {
		http.Error(w, "gagal mengubah status", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/user?msg="+msg, http.StatusSeeOther)
}

func (s *app) createUser(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.checkCSRF(r, sess.CSRF) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	username, okName := parseUsername(r.Form.Get("username"))
	password := r.Form.Get("password")
	if !okName || !validPassword(password) {
		http.Redirect(w, r, "/admin?msg=bad-user", http.StatusSeeOther)
		return
	}
	if err := createUser(s.db, username, password, r.Form.Get("can_add") == "1"); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			http.Redirect(w, r, "/admin?msg=user-exists", http.StatusSeeOther)
			return
		}
		http.Error(w, "gagal menyimpan", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin?msg=user-created", http.StatusSeeOther)
}

func (s *app) setCanAdd(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.checkCSRF(r, sess.CSRF) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	id, okID := formID(r)
	allow := r.Form.Get("allow") == "1"
	if !okID || setUserCanAdd(s.db, id, allow) != nil {
		http.Error(w, "gagal mengubah izin", http.StatusBadRequest)
		return
	}
	msg := "can-add-off"
	if allow {
		msg = "can-add"
	}
	http.Redirect(w, r, "/admin?msg="+msg+"&open="+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

func (s *app) changePassword(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.checkCSRF(r, sess.CSRF) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	id, okID := formID(r)
	password := r.Form.Get("password")
	if !okID || !validPassword(password) || setUserPassword(s.db, id, password) != nil {
		http.Error(w, "gagal mengubah kata sandi", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin?msg=password", http.StatusSeeOther)
}

func (s *app) removeUser(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.checkCSRF(r, sess.CSRF) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	id, okID := formID(r)
	if !okID || deleteUser(s.db, id) != nil {
		http.Error(w, "gagal menghapus user", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin?msg=user-deleted", http.StatusSeeOther)
}

func (s *app) impersonate(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.checkCSRF(r, sess.CSRF) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	id, okID := formID(r)
	if !okID {
		http.Error(w, "user tidak ditemukan", http.StatusBadRequest)
		return
	}
	if _, err := userByID(s.db, id); err != nil {
		http.Error(w, "user tidak ditemukan", http.StatusBadRequest)
		return
	}
	s.setSession(w, r, "user", id, true)
	http.Redirect(w, r, "/user", http.StatusSeeOther)
}

func (s *app) stopImpersonate(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	if !sess.Impersonating || !s.checkCSRF(r, sess.CSRF) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	s.setSession(w, r, "admin", 0, false)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *app) assignLicense(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if !s.checkCSRF(r, sess.CSRF) {
		http.Error(w, "sesi tidak valid", http.StatusBadRequest)
		return
	}
	licenseID, okLic := formID(r)
	userID, okUser := parseAccount(r.Form.Get("user_id"))
	if !okLic || !okUser || assignLicense(s.db, licenseID, userID) != nil {
		http.Error(w, "gagal memindahkan lisensi", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/admin?msg=assigned", http.StatusSeeOther)
}

type eaRequest struct {
	Account  json.Number `json:"account"`
	Server   string      `json:"server"`
	Name     string      `json:"name"`
	Product  string      `json:"product"`
	Pass     string      `json:"pass"`
	Day      string      `json:"day"`
	Profit   json.Number `json:"profit"`
	Currency string      `json:"currency"`
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
	status, expires, err := licenseStatus(s.db, account, req.Product, server, cleanAccountName(req.Name))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Server lisensi bermasalah"})
		return
	}
	switch status {
	case "ok":
		if req.Profit != "" || req.Day != "" {
			profit, day, currency, valid := parseProfitReport(req)
			if !valid {
				writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Data profit tidak valid"})
				return
			}
			if err := saveProfit(s.db, account, req.Product, day, profit, currency); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "Server lisensi bermasalah"})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": "run", "expires": expires})
	case "expired":
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Masa sewa EA telah berakhir"})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "Akun tidak terdaftar"})
	}
}

func cleanAccountName(s string) string {
	out := make([]rune, 0, 80)
	for _, r := range strings.TrimSpace(s) {
		if r < 32 || r == 127 {
			continue
		}
		out = append(out, r)
		if len(out) == 80 {
			break
		}
	}
	return string(out)
}

func parseProfitReport(req eaRequest) (float64, string, string, bool) {
	if req.Profit == "" || req.Day == "" {
		return 0, "", "", false
	}
	profit, err := req.Profit.Float64()
	if err != nil || math.IsNaN(profit) || math.IsInf(profit, 0) {
		return 0, "", "", false
	}
	day, ok := parseDate(req.Day)
	if !ok {
		return 0, "", "", false
	}
	t, _ := time.Parse("2006-01-02", day)
	now := time.Now().UTC()
	if t.Before(now.AddDate(-1, 0, 0)) || t.After(now.AddDate(0, 0, 2)) {
		return 0, "", "", false
	}
	return profit, day, cleanCurrency(req.Currency), true
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
