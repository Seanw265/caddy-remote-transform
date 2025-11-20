package caddydynamictransform

import (
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("dynamic_transform", parseCaddyfile)
}

// parseCaddyfile parses the dynamic_transform directive from a Caddyfile.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(DynamicTransform)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *DynamicTransform) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume directive name if not already consumed
	if !d.Next() {
		return d.ArgErr()
	}

	// Parse the configuration block
	for d.NextBlock(0) {
		switch d.Val() {
		case "endpoint":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.Endpoint = d.Val()
		case "timeout":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid timeout: %v", err)
			}
			m.Timeout = caddy.Duration(dur)
		case "max_body_bytes":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var maxBytes int64
			if _, err := fmt.Sscanf(d.Val(), "%d", &maxBytes); err != nil {
				return d.Errf("invalid max_body_bytes: %v", err)
			}
			m.MaxBodyBytes = maxBytes
		case "include_body":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val := strings.ToLower(d.Val())
			m.IncludeBody = val == "true" || val == "on" || val == "yes" || val == "1"
		case "body_encoding":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.BodyEncoding = d.Val()
		case "strip_headers":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.StripHeaders = append(m.StripHeaders, args...)
		case "error_mode":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.ErrorMode = d.Val()
		default:
			return d.Errf("unknown option: %s", d.Val())
		}
	}
	return nil
}

