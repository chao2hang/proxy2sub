package main

import (
	"database/sql"
	"encoding/json"

	_ "modernc.org/sqlite"
)

// Store 基于 SQLite 的节点存储。
type Store struct {
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // 单写者，避免 SQLITE_BUSY
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS nodes (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			protocol    TEXT NOT NULL,
			server      TEXT NOT NULL,
			port        INTEGER NOT NULL,
			name        TEXT NOT NULL,
			ip          TEXT NOT NULL DEFAULT '',
			country     TEXT NOT NULL DEFAULT 'ZZ',
			latency_ms  INTEGER NOT NULL DEFAULT 0,
			config      TEXT NOT NULL,
			last_check  INTEGER NOT NULL DEFAULT 0,
			created_at  INTEGER NOT NULL DEFAULT 0,
			UNIQUE(protocol, server, port)
		);`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Exists 判断 (protocol, server, port) 是否已存在。
func (s *Store) Exists(n *Node) (bool, error) {
	var one int
	err := s.db.QueryRow(
		"SELECT 1 FROM nodes WHERE protocol=? AND server=? AND port=? LIMIT 1",
		n.Protocol, n.Server, n.Port).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) Insert(n *Node) error {
	cfg, err := json.Marshal(n)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO nodes (protocol, server, port, name, ip, country, latency_ms, config, last_check, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		n.Protocol, n.Server, n.Port, n.Name, n.IP, n.Country, n.LatencyMS,
		string(cfg), n.LastCheck, n.CreatedAt)
	return err
}

// UpdateResult 刷新测活结果与地理信息。
func (s *Store) UpdateResult(n *Node) error {
	_, err := s.db.Exec(`
		UPDATE nodes SET name=?, ip=?, country=?, latency_ms=?, last_check=?, config=?
		WHERE id=?`,
		n.Name, n.IP, n.Country, n.LatencyMS, n.LastCheck, mustJSON(n), n.ID)
	return err
}

func (s *Store) Delete(id int64) error {
	_, err := s.db.Exec("DELETE FROM nodes WHERE id=?", id)
	return err
}

// All 返回全部节点。
func (s *Store) All() ([]*Node, error) {
	rows, err := s.db.Query("SELECT id, config FROM nodes")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []*Node
	for rows.Next() {
		var id int64
		var cfg string
		if err := rows.Scan(&id, &cfg); err != nil {
			return nil, err
		}
		var n Node
		if err := json.Unmarshal([]byte(cfg), &n); err != nil {
			continue
		}
		n.ID = id
		nodes = append(nodes, &n)
	}
	return nodes, rows.Err()
}

func (s *Store) Count() (int, error) {
	var c int
	err := s.db.QueryRow("SELECT COUNT(*) FROM nodes").Scan(&c)
	return c, err
}

func mustJSON(n *Node) string {
	b, err := json.Marshal(n)
	if err != nil {
		return "{}"
	}
	return string(b)
}
