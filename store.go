package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type License struct {
	ID         int64
	Account    int64
	Product    string
	Expires    string
	Note       string
	Active     bool
	ServerName string
	CreatedAt  string
}

func (l License) ProductLabel() string {
	switch l.Product {
	case "btcusd":
		return "BTCUSD"
	case "xau":
		return "XAU"
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
);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
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

func upsertLicense(db *sql.DB, account int64, product, expires, note string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
INSERT INTO licenses(account, product, expires, note, active, server_name, created_at)
VALUES(?, ?, ?, ?, 1, '', ?)
ON CONFLICT(account, product) DO UPDATE SET
  expires=excluded.expires,
  note=excluded.note,
  active=1`, account, product, expires, note, now)
	return err
}

func listLicenses(db *sql.DB) ([]License, error) {
	rows, err := db.Query(`SELECT id, account, product, expires, note, active, server_name, created_at
		FROM licenses ORDER BY account, product`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []License
	for rows.Next() {
		var l License
		var active int
		if err := rows.Scan(&l.ID, &l.Account, &l.Product, &l.Expires, &l.Note, &active, &l.ServerName, &l.CreatedAt); err != nil {
			return nil, err
		}
		l.Active = active == 1
		out = append(out, l)
	}
	return out, rows.Err()
}

func setExpiry(db *sql.DB, id int64, expires string) error {
	res, err := db.Exec(`UPDATE licenses SET expires=?, active=1 WHERE id=?`, expires, id)
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

func setActive(db *sql.DB, id int64, active bool) error {
	v := 0
	if active {
		v = 1
	}
	res, err := db.Exec(`UPDATE licenses SET active=? WHERE id=?`, v, id)
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

// licenseStatus: ok, missing, expired.
func licenseStatus(db *sql.DB, account int64, product, server string) (string, string, error) {
	var id int64
	var expires string
	var active int
	err := db.QueryRow(`SELECT id, expires, active FROM licenses WHERE account=? AND product=?`, account, product).
		Scan(&id, &expires, &active)
	if err == sql.ErrNoRows || (err == nil && active != 1) {
		return "missing", "", nil
	}
	if err != nil {
		return "", "", err
	}
	today := time.Now().UTC().Format("2006-01-02")
	if expires < today {
		return "expired", expires, nil
	}
	_, _ = db.Exec(`UPDATE licenses SET server_name=? WHERE id=?`, server, id)
	return "ok", expires, nil
}
