# sec

- Namespace: lifecycle
- Type: custom
- Category: Test
- Points: 1

## Description

A service under its own seccomp profile, which lifecycle.sh writes beside
this file at run time.

## Details

Visit `{{server}}:{{port}}`.

## Challenge Options

```yaml
seccomp:
  profile: profile.json
```
