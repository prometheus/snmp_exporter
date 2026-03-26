package config

import (
    "testing"
    "gopkg.in/yaml.v2"
  )

func TestWalkParamsRetriesIsolation(t *testing.T) {
    content := `
    module1:
      walk_params:
          retries: 5
          module2:
          `
    var cfg Config
    if err := yaml.Unmarshal([]byte(content), &cfg); err != nil {
          t.Fatalf("Error unmarshaling content: %v", err)
        }

    m1 := cfg["module1"]
    m2 := cfg["module2"]

    if m1.WalkParams.Retries == nil {
          t.Fatal("module1 retries is nil")
        }
    if m2.WalkParams.Retries == nil {
          t.Fatal("module2 retries is nil")
        }

    if *m1.WalkParams.Retries != 5 {
          t.Errorf("module1 retries: expected 5, got %d", *m1.WalkParams.Retries)
        }

    if m1.WalkParams.Retries == m2.WalkParams.Retries {
          t.Error("module1 and module2 share the same Retries pointer")
        }
  }
