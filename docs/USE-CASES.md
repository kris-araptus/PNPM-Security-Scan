# npm Security Scanner - Use Cases

Complete guide to all the ways you can use this security scanner.

---

## Table of Contents

1. [Manual Installation (Copy Files)](#1-manual-installation-copy-files)
2. [npm Package Installation](#2-npm-package-installation)
3. [Global CLI Tool](#3-global-cli-tool)
4. [CI/CD Pipeline Integration](#4-cicd-pipeline-integration)
5. [Pre-commit Hooks](#5-pre-commit-hooks)
6. [Monorepo / Workspace Usage](#6-monorepo--workspace-usage)
7. [Standalone Project Scanner](#7-standalone-project-scanner)
8. [Docker Container](#8-docker-container)
9. [Security Audit Workflow](#9-security-audit-workflow)
10. [Automated Scheduled Scans](#10-automated-scheduled-scans)

---

## 1. Manual Installation (Copy Files)

**Best for:** Quick setup, projects without npm publishing

### Setup

```bash
# Navigate to your project
cd your-project

# Copy scanner files
cp -r /path/to/PNPM-Security-Scan/scripts ./scripts
cp -r /path/to/PNPM-Security-Scan/security ./security

# Make executable
chmod +x scripts/security-scan.js
```

### Add to package.json

```json
{
  "scripts": {
    "security:scan": "node scripts/security-scan.js",
    "security:scan:verbose": "node scripts/security-scan.js --verbose",
    "security:scan:json": "node scripts/security-scan.js --json",
    "security:scan:strict": "node scripts/security-scan.js --strict"
  }
}
```

### Usage

```bash
pnpm run security:scan
```

### Pros & Cons

✅ No npm publish required  
✅ Full control over threat database  
✅ Easy to customize  
❌ Manual updates needed  
❌ Must copy to each project  

---

## 2. npm Package Installation

**Best for:** Teams, multiple projects, easy updates

### Publish the Package

```bash
# In PNPM-Security-Scan directory
cd /path/to/PNPM-Security-Scan

# Update package name if needed
# Edit package.json "name" field

# Publish to npm
pnpm publish --access public
```

### Install in Your Project

```bash
# Install as dev dependency
pnpm add -D @kris-araptus/npm-security-scanner

# Or with npm
npm install -D @kris-araptus/npm-security-scanner
```

### Add Scripts to Your Project

```json
{
  "scripts": {
    "security:scan": "security-scan",
    "security:scan:verbose": "security-scan --verbose"
  }
}
```

### Usage

```bash
pnpm run security:scan
```

### Pros & Cons

✅ Easy to install across projects  
✅ Updates via `pnpm update`  
✅ Team can all use same version  
❌ Requires npm account  
❌ Public or paid private registry  

---

## 3. Global CLI Tool

**Best for:** Scanning any project from anywhere

### Install Globally

```bash
# Install globally
pnpm add -g @kris-araptus/npm-security-scanner

# Or with npm
npm install -g @kris-araptus/npm-security-scanner
```

### Usage

```bash
# Navigate to any project
cd /path/to/any-project

# Run scanner
security-scan
security-scan --verbose
security-scan --json
```

### Scan Multiple Projects

```bash
# Scan several projects
for dir in ~/projects/*/; do
  echo "Scanning $dir"
  cd "$dir" && security-scan
done
```

### Pros & Cons

✅ Scan any project instantly  
✅ No per-project setup  
✅ Great for auditing multiple projects  
❌ Must manage global install  
❌ Different machines need separate installs  

---

## 4. CI/CD Pipeline Integration

**Best for:** Automated security gates, blocking bad deployments

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 9 * * 1'  # Weekly Monday 9am

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup pnpm
        uses: pnpm/action-setup@v2
        with:
          version: 8
          
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
          
      - name: Install dependencies
        run: pnpm install
        
      - name: Run security scan
        run: pnpm run security:scan --strict
        
      - name: Upload scan results
        if: always()
        run: pnpm run security:scan --json > security-report.json
        
      - name: Archive security report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security

security_scan:
  stage: security
  image: node:20
  before_script:
    - npm install -g pnpm
    - pnpm install
  script:
    - pnpm run security:scan --strict
  artifacts:
    when: always
    paths:
      - security-report.json
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

### Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '20.x'
      
  - script: |
      npm install -g pnpm
      pnpm install
    displayName: 'Install dependencies'
    
  - script: pnpm run security:scan --strict
    displayName: 'Security Scan'
    
  - script: pnpm run security:scan --json > $(Build.ArtifactStagingDirectory)/security-report.json
    displayName: 'Generate Report'
    condition: always()
    
  - publish: $(Build.ArtifactStagingDirectory)/security-report.json
    artifact: SecurityReport
    condition: always()
```

### Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
image: node:20

pipelines:
  default:
    - step:
        name: Security Scan
        caches:
          - node
        script:
          - npm install -g pnpm
          - pnpm install
          - pnpm run security:scan --strict
        artifacts:
          - security-report.json
```

### CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/node:20.0
    steps:
      - checkout
      - run:
          name: Install pnpm
          command: npm install -g pnpm
      - run:
          name: Install dependencies
          command: pnpm install
      - run:
          name: Security Scan
          command: pnpm run security:scan --strict
      - store_artifacts:
          path: security-report.json

workflows:
  security:
    jobs:
      - security-scan
```

### Pros & Cons

✅ Automated security checks  
✅ Blocks compromised dependencies  
✅ Audit trail with artifacts  
✅ Scheduled scans for monitoring  
❌ Requires CI/CD setup  
❌ May slow down pipelines  

---

## 5. Pre-commit Hooks

**Best for:** Catching issues before they're committed

### Using Husky

```bash
# Install husky
pnpm add -D husky

# Initialize husky
pnpm exec husky init
```

```bash
# .husky/pre-commit
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

pnpm run security:scan
```

### Using lint-staged

```bash
pnpm add -D husky lint-staged
```

```json
// package.json
{
  "lint-staged": {
    "package.json": "pnpm run security:scan"
  },
  "husky": {
    "hooks": {
      "pre-commit": "lint-staged"
    }
  }
}
```

### Using simple-git-hooks

```bash
pnpm add -D simple-git-hooks
```

```json
// package.json
{
  "simple-git-hooks": {
    "pre-commit": "pnpm run security:scan"
  }
}
```

### Using lefthook

```yaml
# lefthook.yml
pre-commit:
  commands:
    security-scan:
      run: pnpm run security:scan
```

### Pros & Cons

✅ Catches issues immediately  
✅ Prevents bad commits  
✅ Developer-friendly workflow  
❌ Can slow down commits  
❌ Developers can bypass with `--no-verify`  

---

## 6. Monorepo / Workspace Usage

**Best for:** Projects with multiple packages

### pnpm Workspaces

```yaml
# pnpm-workspace.yaml
packages:
  - 'packages/*'
  - 'apps/*'
```

```json
// Root package.json
{
  "scripts": {
    "security:scan": "pnpm -r run security:scan",
    "security:scan:all": "pnpm -r --parallel run security:scan"
  }
}
```

### Turborepo

```json
// turbo.json
{
  "pipeline": {
    "security:scan": {
      "cache": false
    }
  }
}
```

```bash
# Run across all packages
turbo run security:scan
```

### Nx

```json
// nx.json
{
  "targetDefaults": {
    "security:scan": {
      "cache": false
    }
  }
}
```

```bash
# Run across all projects
nx run-many --target=security:scan
```

### Lerna

```bash
# Run in all packages
lerna run security:scan
```

### Scan Root + All Packages Script

```bash
#!/bin/bash
# scan-all.sh

echo "🔍 Scanning root package..."
pnpm run security:scan

echo ""
echo "🔍 Scanning workspace packages..."
for dir in packages/*/; do
  if [ -f "$dir/package.json" ]; then
    echo "Scanning $dir"
    (cd "$dir" && pnpm run security:scan) || exit 1
  fi
done

echo ""
echo "✅ All packages scanned!"
```

### Pros & Cons

✅ Scan entire monorepo  
✅ Catch issues in any package  
✅ Parallel scanning for speed  
❌ More complex setup  
❌ May need per-package config  

---

## 7. Standalone Project Scanner

**Best for:** Auditing third-party projects, one-off scans

### Using npx (No Install)

```bash
# Scan any project without installing
cd /path/to/project
npx @kris-araptus/npm-security-scanner
npx @kris-araptus/npm-security-scanner --verbose
```

### Audit Script

```bash
#!/bin/bash
# audit-project.sh

PROJECT_PATH=${1:-.}

echo "🔍 Security Audit: $PROJECT_PATH"
echo "================================"

cd "$PROJECT_PATH"

# Check if package.json exists
if [ ! -f "package.json" ]; then
  echo "❌ No package.json found"
  exit 1
fi

# Run security scan
npx @kris-araptus/npm-security-scanner --verbose

# Also run npm audit
echo ""
echo "📋 npm audit results:"
pnpm audit --prod 2>/dev/null || npm audit --prod 2>/dev/null

echo ""
echo "✅ Audit complete"
```

### Usage

```bash
# Audit current directory
./audit-project.sh

# Audit specific project
./audit-project.sh /path/to/project

# Audit multiple projects
for project in ~/code/*/; do
  ./audit-project.sh "$project"
done
```

### Pros & Cons

✅ No permanent installation  
✅ Audit any project quickly  
✅ Great for code reviews  
❌ Slower (downloads each time)  
❌ Requires network access  

---

## 8. Docker Container

**Best for:** Isolated scanning, CI environments, consistent results

### Dockerfile

```dockerfile
# Dockerfile
FROM node:20-alpine

WORKDIR /scanner

# Copy scanner files
COPY scripts/ ./scripts/
COPY security/ ./security/
COPY package.json ./

# Make executable
RUN chmod +x scripts/security-scan.js

# Set entrypoint
ENTRYPOINT ["node", "scripts/security-scan.js"]
CMD ["--help"]
```

### Build and Use

```bash
# Build the image
docker build -t npm-security-scanner .

# Scan a project (mount project directory)
docker run --rm -v /path/to/project:/project -w /project npm-security-scanner

# With options
docker run --rm -v $(pwd):/project -w /project npm-security-scanner --verbose
docker run --rm -v $(pwd):/project -w /project npm-security-scanner --json
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'
services:
  security-scan:
    build: .
    volumes:
      - ./:/project
    working_dir: /project
    command: ["--verbose"]
```

```bash
docker-compose run security-scan
```

### In CI/CD with Docker

```yaml
# GitHub Actions with Docker
- name: Security Scan (Docker)
  run: |
    docker run --rm -v ${{ github.workspace }}:/project -w /project \
      npm-security-scanner --strict
```

### Pros & Cons

✅ Consistent environment  
✅ Isolated from host  
✅ Easy CI/CD integration  
✅ No Node.js required on host  
❌ Docker overhead  
❌ Image management  

---

## 9. Security Audit Workflow

**Best for:** Comprehensive security review

### Complete Audit Script

```bash
#!/bin/bash
# full-security-audit.sh

set -e

PROJECT_PATH=${1:-.}
REPORT_DIR="./security-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "🛡️  Full Security Audit"
echo "======================="
echo "Project: $PROJECT_PATH"
echo "Time: $TIMESTAMP"
echo ""

cd "$PROJECT_PATH"
mkdir -p "$REPORT_DIR"

# 1. Custom Security Scanner
echo "📋 Step 1: Running npm Security Scanner..."
pnpm run security:scan --json > "$REPORT_DIR/scan-$TIMESTAMP.json" 2>&1 || true
pnpm run security:scan:verbose

# 2. npm/pnpm Audit
echo ""
echo "📋 Step 2: Running pnpm audit..."
pnpm audit --json > "$REPORT_DIR/audit-$TIMESTAMP.json" 2>&1 || true
pnpm audit || true

# 3. Check for outdated packages
echo ""
echo "📋 Step 3: Checking outdated packages..."
pnpm outdated --json > "$REPORT_DIR/outdated-$TIMESTAMP.json" 2>&1 || true
pnpm outdated || true

# 4. License check (if license-checker installed)
echo ""
echo "📋 Step 4: Checking licenses..."
if command -v license-checker &> /dev/null; then
  license-checker --json > "$REPORT_DIR/licenses-$TIMESTAMP.json"
  license-checker --summary
else
  echo "⚠️  license-checker not installed (npm i -g license-checker)"
fi

# 5. Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 AUDIT SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Reports saved to: $REPORT_DIR/"
ls -la "$REPORT_DIR"/*-$TIMESTAMP.json 2>/dev/null || true
echo ""
echo "✅ Full security audit complete!"
```

### Usage

```bash
chmod +x full-security-audit.sh
./full-security-audit.sh
./full-security-audit.sh /path/to/project
```

### Pros & Cons

✅ Comprehensive security review  
✅ Multiple tools combined  
✅ Historical reports  
❌ Takes longer to run  
❌ Requires multiple tools  

---

## 10. Automated Scheduled Scans

**Best for:** Continuous monitoring, catching new threats

### Cron Job (Local)

```bash
# Edit crontab
crontab -e

# Add daily scan at 9am
0 9 * * * cd /path/to/project && /usr/local/bin/pnpm run security:scan >> /var/log/security-scan.log 2>&1

# Weekly comprehensive scan on Monday
0 10 * * 1 cd /path/to/project && /path/to/full-security-audit.sh >> /var/log/security-audit.log 2>&1
```

### GitHub Actions Scheduled

```yaml
# .github/workflows/scheduled-scan.yml
name: Scheduled Security Scan

on:
  schedule:
    - cron: '0 9 * * *'  # Daily at 9am UTC
  workflow_dispatch:  # Manual trigger

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v2
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
      - run: pnpm install
      - run: pnpm run security:scan --json > report.json
      
      - name: Check for issues
        id: check
        run: |
          ISSUES=$(cat report.json | jq '.totalIssues')
          echo "issues=$ISSUES" >> $GITHUB_OUTPUT
          
      - name: Create Issue if problems found
        if: steps.check.outputs.issues != '0'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('report.json', 'utf8'));
            
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: '🚨 Security Scan Found Issues',
              body: `## Security Scan Results\n\n` +
                    `**Issues Found:** ${report.totalIssues}\n\n` +
                    `**Critical:** ${report.results.critical.length}\n` +
                    `**High:** ${report.results.high.length}\n\n` +
                    `[View full report](${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId})`
            });
```

### Slack Notification

```yaml
# Add to GitHub Actions workflow
- name: Notify Slack
  if: steps.check.outputs.issues != '0'
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "🚨 Security issues detected in ${{ github.repository }}",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*Security Scan Alert*\n${{ steps.check.outputs.issues }} issues found"
            }
          }
        ]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### Pros & Cons

✅ Catches new threats automatically  
✅ No manual intervention needed  
✅ Alerts when issues arise  
✅ Continuous monitoring  
❌ May create noise/alerts  
❌ Requires notification setup  

---

## Quick Reference: Which Use Case?

| Scenario | Recommended Use Case |
|----------|---------------------|
| Single project, quick setup | Manual Installation |
| Team with multiple projects | npm Package Installation |
| Security professional auditing | Global CLI Tool |
| Production deployments | CI/CD Pipeline |
| Developer workflow | Pre-commit Hooks |
| Large codebase | Monorepo Usage |
| Code review / audit | Standalone Scanner |
| Isolated environment | Docker Container |
| Comprehensive review | Security Audit Workflow |
| Continuous monitoring | Scheduled Scans |

---

## Summary

| Use Case | Complexity | Best For |
|----------|------------|----------|
| Manual Install | ⭐ | Quick start |
| npm Package | ⭐⭐ | Teams |
| Global CLI | ⭐ | Power users |
| CI/CD | ⭐⭐⭐ | Production |
| Pre-commit | ⭐⭐ | Developers |
| Monorepo | ⭐⭐⭐ | Large projects |
| Standalone | ⭐ | Auditing |
| Docker | ⭐⭐ | Isolation |
| Full Audit | ⭐⭐⭐ | Compliance |
| Scheduled | ⭐⭐⭐ | Monitoring |

---

**Version:** 1.0.0  
**Last Updated:** December 9, 2025

