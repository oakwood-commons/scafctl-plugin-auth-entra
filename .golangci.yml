version: "2"

linters:
  enable:
    - errcheck
    - govet
    - ineffassign
    - staticcheck
    - unused
    - revive
    - gosec
    - misspell
  settings:
    gosec:
      excludes:
        - G101
  exclusions:
    rules:
      - path: _test\.go
        linters:
          - gosec
