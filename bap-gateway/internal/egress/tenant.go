package egress

import (
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// DefaultApprovedTenants lists the baseline approved enterprise tenant identifiers.
// Can be augmented or overridden via the BAP_APPROVED_TENANTS environment variable (comma-separated).
var DefaultApprovedTenants = []string{
	"corp-org",
	"corp-internal",
	"123456789012",
	"T-CORP-WORKSPACE",
	"company.internal",
}

// ExtractionResult captures the parsed SaaS service and tenant context for an egress request.
type ExtractionResult struct {
	Service           string // "github", "aws_s3", "slack", "google_workspace", "generic", "unknown"
	TenantID          string // Extracted destination tenant, organization, or account ID
	CanonicalResource string // Normalized destination target (e.g., "github://corp-org/repo", "s3://corp-bucket/...")
	IsMultiTenant     bool   // True if destination is a multi-tenant cloud service requiring identity verification
}

// githubOwnerRegex extracts the org/owner from GitHub path patterns: /repos/{owner}/{repo} or /orgs/{org}
var (
	githubRepoRegex = regexp.MustCompile(`^/repos/([^/?#]+)(?:/([^/?#]+))?`)
	githubOrgRegex  = regexp.MustCompile(`^/orgs/([^/?#]+)`)
)

// ExtractTenant inspects the destination target (rawURL or path) and HTTP headers to determine
// the destination service, tenant ID, and canonical resource URI.
func ExtractTenant(rawURL, method string, headers http.Header) ExtractionResult {
	res := ExtractionResult{
		Service:       "unknown",
		IsMultiTenant: false,
	}

	parsedURL, err := url.Parse(rawURL)
	var host, path string
	if err == nil && parsedURL.Host != "" {
		host = strings.ToLower(parsedURL.Hostname())
		path = parsedURL.Path
	} else {
		// Might be passed as a relative path or host header
		path = rawURL
		if h := headers.Get("Host"); h != "" {
			host = strings.ToLower(strings.Split(h, ":")[0])
		}
	}

	// 1. GitHub (api.github.com, github.com)
	if isGitHub(host, headers) {
		res.Service = "github"
		res.IsMultiTenant = true

		// Check explicit headers first
		if org := headers.Get("X-GitHub-Org"); org != "" {
			res.TenantID = org
		} else if org := headers.Get("X-Tenant-ID"); org != "" {
			res.TenantID = org
		}

		// Fallback to URL path inspection (/repos/{org}/{repo} or /orgs/{org})
		if res.TenantID == "" {
			if m := githubRepoRegex.FindStringSubmatch(path); len(m) > 1 {
				res.TenantID = m[1]
			} else if m := githubOrgRegex.FindStringSubmatch(path); len(m) > 1 {
				res.TenantID = m[1]
			}
		}

		if res.TenantID != "" {
			res.CanonicalResource = "github://" + res.TenantID + path
		} else {
			res.CanonicalResource = "github://unknown" + path
		}
		return res
	}

	// 2. AWS S3 (s3.amazonaws.com, *.s3.amazonaws.com, *.s3.<region>.amazonaws.com)
	if isAWSS3(host, headers) {
		res.Service = "aws_s3"
		res.IsMultiTenant = true

		// Standard S3 expected bucket owner header (AWS 12-digit account ID)
		if owner := headers.Get("x-amz-expected-bucket-owner"); owner != "" {
			res.TenantID = owner
		} else if acct := headers.Get("x-amz-account-id"); acct != "" {
			res.TenantID = acct
		} else if owner := headers.Get("x-amz-bucket-owner"); owner != "" {
			res.TenantID = owner
		} else if t := headers.Get("X-Tenant-ID"); t != "" {
			res.TenantID = t
		}

		bucket := extractS3Bucket(host, path)
		if res.TenantID != "" {
			res.CanonicalResource = "s3://" + bucket + " (account:" + res.TenantID + ")"
		} else {
			res.CanonicalResource = "s3://" + bucket
		}
		return res
	}

	// 3. Slack (api.slack.com, slack.com)
	if isSlack(host, headers) {
		res.Service = "slack"
		res.IsMultiTenant = true

		if team := headers.Get("X-Slack-Team-Id"); team != "" {
			res.TenantID = team
		} else if team := headers.Get("X-Slack-Workspace"); team != "" {
			res.TenantID = team
		} else if t := headers.Get("X-Tenant-ID"); t != "" {
			res.TenantID = t
		}

		// Also check query parameter team_id
		if res.TenantID == "" && parsedURL != nil {
			if team := parsedURL.Query().Get("team_id"); team != "" {
				res.TenantID = team
			}
		}

		if res.TenantID != "" {
			res.CanonicalResource = "slack://" + res.TenantID + path
		} else {
			res.CanonicalResource = "slack://unknown" + path
		}
		return res
	}

	// 4. Google Workspace / Drive (googleapis.com, drive.google.com, docs.google.com)
	if isGoogleWorkspace(host, headers) {
		res.Service = "google_workspace"
		res.IsMultiTenant = true

		if domain := headers.Get("X-Goog-Allowed-Domains"); domain != "" {
			res.TenantID = domain
		} else if proj := headers.Get("X-Goog-User-Project"); proj != "" {
			res.TenantID = proj
		} else if t := headers.Get("X-Tenant-ID"); t != "" {
			res.TenantID = t
		}

		if res.TenantID != "" {
			res.CanonicalResource = "google://" + res.TenantID + path
		} else {
			res.CanonicalResource = "google://unknown" + path
		}
		return res
	}

	// 5. Generic Multi-Tenant Headers (X-Tenant-ID, X-Org-ID, X-Account-ID)
	if t := headers.Get("X-Tenant-ID"); t != "" {
		res.Service = "generic"
		res.TenantID = t
		res.CanonicalResource = host + path
		res.IsMultiTenant = true
		return res
	} else if org := headers.Get("X-Org-ID"); org != "" {
		res.Service = "generic"
		res.TenantID = org
		res.CanonicalResource = host + path
		res.IsMultiTenant = true
		return res
	} else if acct := headers.Get("X-Account-ID"); acct != "" {
		res.Service = "generic"
		res.TenantID = acct
		res.CanonicalResource = host + path
		res.IsMultiTenant = true
		return res
	}

	// Non-multi-tenant or standard internal endpoint
	res.CanonicalResource = host + path
	return res
}

// GetApprovedTenants returns the list of valid enterprise tenants configured or defaulted.
func GetApprovedTenants() []string {
	if envList := os.Getenv("BAP_APPROVED_TENANTS"); envList != "" {
		parts := strings.Split(envList, ",")
		var clean []string
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				clean = append(clean, trimmed)
			}
		}
		if len(clean) > 0 {
			return clean
		}
	}
	return DefaultApprovedTenants
}

// IsTenantApproved checks whether tenantID is member of the approved tenant set (case-insensitive).
func IsTenantApproved(tenantID string, approvedList []string) bool {
	if tenantID == "" {
		return false
	}
	norm := strings.TrimSpace(strings.ToLower(tenantID))
	for _, a := range approvedList {
		if strings.TrimSpace(strings.ToLower(a)) == norm {
			return true
		}
	}
	return false
}

func isGitHub(host string, headers http.Header) bool {
	if host == "api.github.com" || host == "github.com" || strings.HasSuffix(host, ".github.com") {
		return true
	}
	if headers.Get("X-GitHub-Org") != "" || headers.Get("X-GitHub-Target") != "" {
		return true
	}
	return false
}

func isAWSS3(host string, headers http.Header) bool {
	if host == "s3.amazonaws.com" || strings.HasSuffix(host, ".s3.amazonaws.com") || strings.Contains(host, ".s3.") {
		return true
	}
	if headers.Get("x-amz-expected-bucket-owner") != "" || headers.Get("x-amz-account-id") != "" || headers.Get("x-amz-bucket-owner") != "" {
		return true
	}
	return false
}

func isSlack(host string, headers http.Header) bool {
	if host == "slack.com" || host == "api.slack.com" || strings.HasSuffix(host, ".slack.com") {
		return true
	}
	if headers.Get("X-Slack-Team-Id") != "" || headers.Get("X-Slack-Workspace") != "" {
		return true
	}
	return false
}

func isGoogleWorkspace(host string, headers http.Header) bool {
	if host == "googleapis.com" || strings.HasSuffix(host, ".googleapis.com") || host == "drive.google.com" || host == "docs.google.com" {
		return true
	}
	if headers.Get("X-Goog-Allowed-Domains") != "" {
		return true
	}
	return false
}

func extractS3Bucket(host, path string) string {
	// Virtual-hosted style: <bucket>.s3.<region>.amazonaws.com or <bucket>.s3.amazonaws.com
	if strings.Contains(host, ".s3") {
		parts := strings.Split(host, ".s3")
		if parts[0] != "" && parts[0] != "s3" {
			return parts[0]
		}
	}
	// Path style: s3.amazonaws.com/<bucket>/<key>
	clean := strings.TrimPrefix(path, "/")
	if clean != "" {
		return strings.Split(clean, "/")[0]
	}
	return "unknown-bucket"
}
