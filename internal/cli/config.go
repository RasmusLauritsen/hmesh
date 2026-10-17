package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/RasmusLauritsen/huawei-mesh3-cli/internal/router"
)

type config struct {
	Router   string `json:"router"`
	Username string `json:"username"`
	CAFile   string `json:"ca_file,omitempty"`
}

func configPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", router.Fail("usage", "cannot determine config directory; use --config")
	}
	return filepath.Join(dir, "hmesh", "config.json"), nil
}
func loadConfig(path string) (config, error) {
	c := config{Router: "https://192.168.3.1", Username: "admin"}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, router.Fail("usage", "cannot read config file")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return c, router.Fail("usage", "invalid config file (only router, username and ca_file are supported)")
	}
	if d.Decode(new(any)) != io.EOF {
		return c, router.Fail("usage", "unexpected data in config file")
	}
	return c, nil
}
func saveConfig(path string, c config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return router.Fail("usage", "cannot create config directory")
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".hmesh-config-*")
	if err != nil {
		return router.Fail("usage", "cannot create config file")
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(b, '\n')); err != nil {
		f.Close()
		return router.Fail("usage", "cannot write config file")
	}
	if err = f.Close(); err != nil {
		return router.Fail("usage", "cannot close config file")
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return router.Fail("usage", "cannot replace config file")
	}
	return nil
}
