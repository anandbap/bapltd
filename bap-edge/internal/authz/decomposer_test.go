package authz

import (
	"testing"
)

func TestDecomposer(t *testing.T) {
	tests := []struct {
		name             string
		executable       string
		fullCommand      string
		args             string
		expectedAction   string
		expectedResource string
		expectedType     string
	}{
		// Git test cases
		{
			name:             "git status",
			executable:       "git",
			fullCommand:      "git status",
			expectedAction:   "git:inspect:read",
			expectedResource: "repo:local",
			expectedType:     "read",
		},
		{
			name:             "git push origin main",
			executable:       "git",
			fullCommand:      "git push origin main",
			expectedAction:   "git:push:write",
			expectedResource: "git://origin/main",
			expectedType:     "write",
		},
		{
			name:             "git clone repository",
			executable:       "git",
			fullCommand:      "git clone https://github.com/org/repo.git",
			expectedAction:   "git:clone:read",
			expectedResource: "https://github.com/org/repo.git",
			expectedType:     "read",
		},
		{
			name:             "git commit changes",
			executable:       "git",
			fullCommand:      "git commit -m 'feat: update auth'",
			expectedAction:   "git:commit:write",
			expectedResource: "repo:local",
			expectedType:     "write",
		},
		{
			name:             "git clean delete",
			executable:       "git",
			fullCommand:      "git clean -fd",
			expectedAction:   "git:clean:delete",
			expectedResource: "repo:local",
			expectedType:     "delete",
		},

		// Kubernetes & Helm test cases
		{
			name:             "kubectl get pods production",
			executable:       "kubectl",
			fullCommand:      "kubectl get pods -n production",
			expectedAction:   "k8s:pods:read",
			expectedResource: "k8s://production/pods",
			expectedType:     "read",
		},
		{
			name:             "kubectl apply deployment",
			executable:       "kubectl",
			fullCommand:      "kubectl apply -f deployment.yaml -n staging",
			expectedAction:   "k8s:deployment.yaml:write",
			expectedResource: "k8s://staging/deployment.yaml",
			expectedType:     "write",
		},
		{
			name:             "helm list releases",
			executable:       "helm",
			fullCommand:      "helm list -n default",
			expectedAction:   "helm:releases:read",
			expectedResource: "helm://default/all",
			expectedType:     "read",
		},

		// Databases test cases
		{
			name:             "psql select query",
			executable:       "psql",
			fullCommand:      "psql -d finance -c 'SELECT * FROM ledgers'",
			expectedAction:   "db:query:read",
			expectedResource: "db://finance",
			expectedType:     "read",
		},
		{
			name:             "psql drop table destructive",
			executable:       "psql",
			fullCommand:      "psql -d finance -c 'DROP TABLE users'",
			expectedAction:   "db:query:drop",
			expectedResource: "db://finance",
			expectedType:     "delete",
		},

		// Cloud CLIs test cases
		{
			name:             "aws s3 copy",
			executable:       "aws",
			fullCommand:      "aws s3 cp file.txt s3://corporate-bucket/data/",
			expectedAction:   "aws:s3:write",
			expectedResource: "s3://corporate-bucket",
			expectedType:     "write",
		},
		{
			name:             "aws secretsmanager read",
			executable:       "aws",
			fullCommand:      "aws secretsmanager get-secret-value --secret-id prod/db",
			expectedAction:   "aws:secretsmanager:read",
			expectedResource: "aws://secretsmanager",
			expectedType:     "read",
		},

		// Containers test cases
		{
			name:             "docker ps list",
			executable:       "docker",
			fullCommand:      "docker ps",
			expectedAction:   "container:ps:read",
			expectedResource: "docker://daemon",
			expectedType:     "read",
		},
		{
			name:             "docker run container",
			executable:       "docker",
			fullCommand:      "docker run -d redis:alpine",
			expectedAction:   "container:run:write",
			expectedResource: "docker://redis:alpine",
			expectedType:     "write",
		},

		// Developer toolchains test cases
		{
			name:             "pytest exec",
			executable:       "pytest",
			fullCommand:      "pytest tests/test_auth.py",
			expectedAction:   "dev:test:exec",
			expectedResource: "fs://tests/test_auth.py",
			expectedType:     "exec",
		},
		{
			name:             "npm install package",
			executable:       "npm",
			fullCommand:      "npm install express",
			expectedAction:   "dev:package:install",
			expectedResource: "npm://packages",
			expectedType:     "write",
		},
		{
			name:             "python script exec",
			executable:       "python",
			fullCommand:      "python manage.py runserver",
			expectedAction:   "dev:python:exec",
			expectedResource: "file://manage.py",
			expectedType:     "exec",
		},

		// Filesystem test cases
		{
			name:             "cat file read",
			executable:       "cat",
			fullCommand:      "cat README.md",
			expectedAction:   "fs:file:read",
			expectedResource: "file://README.md",
			expectedType:     "read",
		},
		{
			name:             "rm file delete",
			executable:       "rm",
			fullCommand:      "rm -f temp.log",
			expectedAction:   "fs:file:delete",
			expectedResource: "file://temp.log",
			expectedType:     "delete",
		},

		// HTTP test cases
		{
			name:             "curl post request",
			executable:       "curl",
			fullCommand:      "curl -X POST https://api.corp.internal/v1/payments",
			expectedAction:   "http:post",
			expectedResource: "https://api.corp.internal/v1/payments",
			expectedType:     "write",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decompose(tt.executable, tt.fullCommand, tt.args)
			if got.CanonicalAction != tt.expectedAction {
				t.Errorf("Decompose(%q).CanonicalAction = %q; want %q", tt.fullCommand, got.CanonicalAction, tt.expectedAction)
			}
			if got.CanonicalResource != tt.expectedResource {
				t.Errorf("Decompose(%q).CanonicalResource = %q; want %q", tt.fullCommand, got.CanonicalResource, tt.expectedResource)
			}
			if got.ActionType != tt.expectedType {
				t.Errorf("Decompose(%q).ActionType = %q; want %q", tt.fullCommand, got.ActionType, tt.expectedType)
			}
		})
	}
}

