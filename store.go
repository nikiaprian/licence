package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var errLicenseTaken = errors.New("lisensi milik user lain")

type License struct {
	ID             int64
	Account        int64
	Product        string
	Expires        string
	Note           string
	Active         bool
	ServerName     string
	AccountName    string
	CreatedAt      string
	Profit         float64
	ProfitDay      string
	ProfitCurrency string
	ProfitAt       string
	UserID         int64
	Running        bool
}

func (l License) NameText() string {
	if l.AccountName == "" {
		return "—"
	}
	return l.AccountName
}

func (l License) ExpiresText() string {
	t, err := time.Parse("2006-01-02", l.Expires)
	if err != nil {
		return l.Expires
	}
	return t.Format("02/01/2006")
}

func (l License) ProductLabel() string {
	switch l.Product {
	case "btcusd":
		return "BTCUSD"
	case "xau":
		return "XAUUSD"
	default:
		return l.Product
	}
}

func openDB(dir string) (*sql.DB, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.Join(dir, "licenses.db") + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	schema := `
CREATE TABLE IF NOT EXISTS licenses (
  id INTEGER PRIMARY KEY,
  account INTEGER NOT NULL,
  product TEXT NOT NULL,
  expires TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  server_name TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE(account, product)
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	for _, col := range []struct{ table, name, decl string }{
		{"licenses", "profit", "REAL NOT NULL DEFAULT 0"},
		{"licenses", "profit_day", "TEXT NOT NULL DEFAULT ''"},
		{"licenses", "profit_currency", "TEXT NOT NULL DEFAULT ''"},
		{"licenses", "profit_at", "TEXT NOT NULL DEFAULT ''"},
		{"licenses", "user_id", "INTEGER NOT NULL DEFAULT 0"},
		{"licenses", "account_name", "TEXT NOT NULL DEFAULT ''"},
		{"users", "can_add", "INTEGER NOT NULL DEFAULT 0"},
		{"licenses", "running", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if err := addColumn(db, col.table, col.name, col.decl); err != nil {
			db.Close()
			return nil, err
		}
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_licenses_user ON licenses(user_id)`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS profit_reports (
  license_id INTEGER NOT NULL,
  day TEXT NOT NULL,
  profit REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT '',
  reported_at TEXT NOT NULL,
  PRIMARY KEY (license_id, day)
)`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`INSERT INTO profit_reports(license_id, day, profit, currency, reported_at)
		SELECT id, profit_day, profit, profit_currency, profit_at FROM licenses
		WHERE profit_day <> '' AND profit_at <> ''
		ON CONFLICT(license_id, day) DO NOTHING`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func addColumn(db *sql.DB, table, name, decl string) error {
	if table != "licenses" && table != "users" {
		return fmt.Errorf("tabel tidak dikenal")
	}
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var col, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &col, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if col == name {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + name + ` ` + decl)
	return err
}

func ensureAdminHash(db *sql.DB, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO settings(key, value) VALUES('admin_hash', ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(hash))
	return err
}

func adminHash(db *sql.DB) (string, error) {
	var hash string
	err := db.QueryRow(`SELECT value FROM settings WHERE key='admin_hash'`).Scan(&hash)
	return hash, err
}

func checkAdminPassword(db *sql.DB, password string) bool {
	hash, err := adminHash(db)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

type AccountUser struct {
	ID        int64
	Username  string
	CreatedAt string
	CanAdd    bool
	Licenses  []License
}

func (u AccountUser) CreatedLabel() string {
	t, err := time.Parse(time.RFC3339, u.CreatedAt)
	if err != nil {
		return u.CreatedAt
	}
	wib := time.FixedZone("WIB", 7*3600)
	return t.In(wib).Format("02/01/2006 15:04")
}

func createUser(db *sql.DB, username, password string, canAdd bool) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	add := 0
	if canAdd {
		add = 1
	}
	_, err = db.Exec(`INSERT INTO users(username, password_hash, created_at, can_add) VALUES(?, ?, ?, ?)`,
		username, string(hash), now, add)
	return err
}

func checkUserPassword(db *sql.DB, username, password string) (int64, bool) {
	var id int64
	var hash string
	err := db.QueryRow(`SELECT id, password_hash FROM users WHERE username=?`, username).Scan(&id, &hash)
	if err != nil {
		return 0, false
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return 0, false
	}
	return id, true
}

func userByID(db *sql.DB, id int64) (AccountUser, error) {
	var u AccountUser
	var canAdd int
	err := db.QueryRow(`SELECT id, username, created_at, can_add FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Username, &u.CreatedAt, &canAdd)
	u.CanAdd = canAdd == 1
	return u, err
}

func setUserCanAdd(db *sql.DB, id int64, allow bool) error {
	v := 0
	if allow {
		v = 1
	}
	res, err := db.Exec(`UPDATE users SET can_add=? WHERE id=?`, v, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("user tidak ditemukan")
	}
	return nil
}

func setUserPassword(db *sql.DB, id int64, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	res, err := db.Exec(`UPDATE users SET password_hash=? WHERE id=?`, string(hash), id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("user tidak ditemukan")
	}
	return nil
}

func deleteUser(db *sql.DB, id int64) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM licenses WHERE user_id=?`, id); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM users WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("user tidak ditemukan")
	}
	return tx.Commit()
}

func listUsersAndLicenses(db *sql.DB) ([]AccountUser, []License, error) {
	rows, err := db.Query(`SELECT id, username, created_at, can_add FROM users ORDER BY username`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var users []AccountUser
	byID := map[int64]int{}
	for rows.Next() {
		var u AccountUser
		var canAdd int
		if err := rows.Scan(&u.ID, &u.Username, &u.CreatedAt, &canAdd); err != nil {
			return nil, nil, err
		}
		u.CanAdd = canAdd == 1
		byID[u.ID] = len(users)
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	all, err := listLicenses(db, 0)
	if err != nil {
		return nil, nil, err
	}
	var loose []License
	for _, l := range all {
		if l.UserID == 0 {
			loose = append(loose, l)
			continue
		}
		if i, ok := byID[l.UserID]; ok {
			users[i].Licenses = append(users[i].Licenses, l)
		}
	}
	return users, loose, nil
}

func saveLicense(db *sql.DB, userID, account int64, product, expires, note string) error {
	var owner int64
	err := db.QueryRow(`SELECT user_id FROM licenses WHERE account=? AND product=?`, account, product).Scan(&owner)
	if err == sql.ErrNoRows {
		now := time.Now().UTC().Format(time.RFC3339)
		_, err = db.Exec(`INSERT INTO licenses(account, product, expires, note, active, server_name, created_at, user_id)
			VALUES(?, ?, ?, ?, 1, '', ?, ?)`, account, product, expires, note, now, userID)
		return err
	}
	if err != nil {
		return err
	}
	if owner != userID {
		return errLicenseTaken
	}
	_, err = db.Exec(`UPDATE licenses SET expires=?, note=?, active=1 WHERE account=? AND product=? AND user_id=?`,
		expires, note, account, product, userID)
	return err
}

func listLicenses(db *sql.DB, userID int64) ([]License, error) {
	query := `SELECT id, account, product, expires, note, active, server_name, account_name, created_at,
		profit, profit_day, profit_currency, profit_at, user_id, running
		FROM licenses`
	var rows *sql.Rows
	var err error
	if userID > 0 {
		rows, err = db.Query(query+` WHERE user_id=? ORDER BY account, product`, userID)
	} else {
		rows, err = db.Query(query + ` ORDER BY account, product`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []License
	for rows.Next() {
		var l License
		var active, running int
		if err := rows.Scan(&l.ID, &l.Account, &l.Product, &l.Expires, &l.Note, &active, &l.ServerName, &l.AccountName, &l.CreatedAt,
			&l.Profit, &l.ProfitDay, &l.ProfitCurrency, &l.ProfitAt, &l.UserID, &running); err != nil {
			return nil, err
		}
		l.Active = active == 1
		l.Running = running == 1
		out = append(out, l)
	}
	return out, rows.Err()
}

func assignLicense(db *sql.DB, licenseID, userID int64) error {
	res, err := db.Exec(`UPDATE licenses SET user_id=? WHERE id=? AND user_id=0`, userID, licenseID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("lisensi tidak ditemukan")
	}
	return nil
}

type dayProfit struct {
	day    string
	profit float64
}

func saveProfit(db *sql.DB, account int64, product, day string, profit float64, currency string) error {
	return saveProfitDays(db, account, product, currency, []dayProfit{{day: day, profit: profit}})
}

func saveProfitDays(db *sql.DB, account int64, product, currency string, days []dayProfit) error {
	if len(days) == 0 {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var id int64
	err := db.QueryRow(`SELECT id FROM licenses WHERE account=? AND product=?`, account, product).Scan(&id)
	if err == sql.ErrNoRows {
		return fmt.Errorf("lisensi tidak ditemukan")
	}
	if err != nil {
		return err
	}
	latest := days[0]
	for _, d := range days[1:] {
		if d.day > latest.day {
			latest = d
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE licenses
		SET profit=?, profit_day=?, profit_currency=?, profit_at=?
		WHERE id=?`, latest.profit, latest.day, currency, now, id); err != nil {
		return err
	}
	for _, d := range days {
		if _, err := tx.Exec(`INSERT INTO profit_reports(license_id, day, profit, currency, reported_at)
			VALUES(?, ?, ?, ?, ?)
			ON CONFLICT(license_id, day) DO UPDATE SET
			  profit=excluded.profit,
			  currency=excluded.currency,
			  reported_at=excluded.reported_at`, id, d.day, d.profit, currency, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func applyProfitSpan(db *sql.DB, from, to string, lists ...[]License) error {
	if from == "" {
		from = "0000-01-01"
	}
	if to == "" {
		to = "9999-12-31"
	}
	rows, err := db.Query(`SELECT license_id, SUM(profit), MIN(day), MAX(day), MAX(currency)
		FROM profit_reports WHERE day>=? AND day<=? GROUP BY license_id`, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	type report struct {
		profit   float64
		minDay   string
		maxDay   string
		currency string
	}
	found := map[int64]report{}
	for rows.Next() {
		var id int64
		var r report
		if err := rows.Scan(&id, &r.profit, &r.minDay, &r.maxDay, &r.currency); err != nil {
			return err
		}
		found[id] = r
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, list := range lists {
		for i := range list {
			r, ok := found[list[i].ID]
			if !ok {
				list[i].Profit = 0
				list[i].ProfitDay = ""
				list[i].ProfitCurrency = ""
				list[i].ProfitAt = ""
				continue
			}
			list[i].Profit = r.profit
			list[i].ProfitDay = daySpanText(r.minDay, r.maxDay)
			list[i].ProfitCurrency = r.currency
			list[i].ProfitAt = r.maxDay
		}
	}
	return nil
}

func daySpanText(minDay, maxDay string) string {
	a := formatISODate(minDay)
	b := formatISODate(maxDay)
	if a == b {
		return a
	}
	return a + " – " + b
}

func formatISODate(iso string) string {
	t, err := time.Parse("2006-01-02", iso)
	if err != nil {
		return iso
	}
	return t.Format("02/01/2006")
}

func (l License) ProfitText() string {
	if l.ProfitAt == "" {
		return "—"
	}
	text := fmt.Sprintf("%.2f", l.Profit)
	if l.ProfitCurrency != "" {
		text += " " + l.ProfitCurrency
	}
	return text
}

func (l License) ProfitClass() string {
	if l.ProfitAt == "" {
		return ""
	}
	if l.Profit < 0 {
		return "off"
	}
	return "on"
}

func cleanCurrency(s string) string {
	out := make([]rune, 0, len(s))
	for _, c := range s {
		if unicode.IsLetter(c) {
			out = append(out, c)
		}
		if len(out) == 8 {
			break
		}
	}
	return string(out)
}

func setExpiry(db *sql.DB, id, userID int64, expires string) error {
	res, err := db.Exec(`UPDATE licenses SET expires=?, active=1 WHERE id=? AND user_id=?`, expires, id, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("lisensi tidak ditemukan")
	}
	return nil
}

func setActive(db *sql.DB, id, userID int64, active bool) error {
	v := 0
	if active {
		v = 1
	}
	res, err := db.Exec(`UPDATE licenses SET active=? WHERE id=? AND user_id=?`, v, id, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("lisensi tidak ditemukan")
	}
	return nil
}

func setRunningByAccount(db *sql.DB, account int64, product string, running bool) error {
	v := 0
	if running {
		v = 1
	}
	res, err := db.Exec(`UPDATE licenses SET running=? WHERE account=? AND product=? AND active=1`, v, account, product)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("lisensi tidak ditemukan")
	}
	return nil
}

func setRunning(db *sql.DB, id, userID int64, running bool) error {
	v := 0
	if running {
		v = 1
	}
	var (
		res sql.Result
		err error
	)
	if userID > 0 {
		res, err = db.Exec(`UPDATE licenses SET running=? WHERE id=? AND user_id=?`, v, id, userID)
	} else {
		res, err = db.Exec(`UPDATE licenses SET running=? WHERE id=?`, v, id)
	}
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("lisensi tidak ditemukan")
	}
	return nil
}

// licenseStatus: ok, missing, expired. mode is run or stop when status is ok.
func licenseStatus(db *sql.DB, account int64, product, server, accountName string) (string, string, string, error) {
	var id int64
	var expires string
	var active, running int
	err := db.QueryRow(`SELECT id, expires, active, running FROM licenses WHERE account=? AND product=?`, account, product).
		Scan(&id, &expires, &active, &running)
	if err == sql.ErrNoRows || (err == nil && active != 1) {
		return "missing", "", "", nil
	}
	if err != nil {
		return "", "", "", err
	}
	today := time.Now().UTC().Format("2006-01-02")
	if expires < today {
		return "expired", expires, "", nil
	}
	if accountName != "" {
		_, _ = db.Exec(`UPDATE licenses SET server_name=?, account_name=? WHERE id=?`, server, accountName, id)
	} else {
		_, _ = db.Exec(`UPDATE licenses SET server_name=? WHERE id=?`, server, id)
	}
	mode := "stop"
	if running == 1 {
		mode = "run"
	}
	return "ok", expires, mode, nil
}
