# Security Scanner Web UI

A beautiful, accessible web interface for the npm Security Scanner. Built with Astro, React, and Tailwind CSS for deployment on Vercel.

## Features

- 🎨 **Araptus-branded design** - Professional purple theme with modern aesthetics
- 📦 **Drag & drop file upload** - Support for package.json and all lock file formats
- 📋 **Paste support** - Just paste your file contents directly
- 🔬 **Deep scanning** - Automatically detects lock files for transitive dependency analysis
- 📊 **Visual results** - Clear severity breakdown and threat visualization
- ⚡ **Instant feedback** - Serverless API for fast scanning
- 📱 **Responsive design** - Works on desktop and mobile

## Supported File Types

- `package.json` - Direct dependencies
- `pnpm-lock.yaml` - Full dependency tree (pnpm)
- `package-lock.json` - Full dependency tree (npm)
- `yarn.lock` - Full dependency tree (yarn)

## Development

```bash
# Install dependencies
pnpm install

# Start dev server
pnpm dev

# Build for production
pnpm build

# Preview production build
pnpm preview
```

## Deployment to Vercel

This project is configured for Vercel deployment out of the box:

1. Push to GitHub
2. Import project in Vercel
3. Deploy!

Or use the Vercel CLI:

```bash
vercel
```

## Tech Stack

- **Framework**: [Astro](https://astro.build) v5
- **UI Library**: [React](https://react.dev) v19
- **Styling**: [Tailwind CSS](https://tailwindcss.com) v4
- **Deployment**: [Vercel](https://vercel.com)
- **Fonts**: Inter, JetBrains Mono

## Project Structure

```
web/
├── src/
│   ├── components/
│   │   └── Scanner.tsx      # Main scanner React component
│   ├── layouts/
│   │   └── Layout.astro     # Base layout with header/footer
│   ├── lib/
│   │   ├── scanner.ts       # Scanning logic
│   │   ├── types.ts         # TypeScript interfaces
│   │   └── threat-db.json   # Threat database
│   ├── pages/
│   │   ├── api/
│   │   │   └── scan.ts      # API endpoint
│   │   └── index.astro      # Home page
│   └── styles/
│       └── global.css       # Global styles + Tailwind
├── public/
│   └── favicon.svg          # Shield icon
├── astro.config.mjs         # Astro configuration
├── package.json
└── tsconfig.json
```

## API

### POST /api/scan

Scan a file for malicious packages.

**Request:**
```json
{
  "content": "{ ... file contents ... }",
  "filename": "package.json"
}
```

**Response:**
```json
{
  "timestamp": "2025-12-09T...",
  "scanMode": "deep",
  "lockFile": "pnpm-lock.yaml",
  "packagesScanned": {
    "total": 150,
    "direct": 20,
    "transitive": 130
  },
  "totalIssues": 2,
  "transitiveIssues": 1,
  "results": {
    "critical": [...],
    "high": [...],
    "medium": [...],
    "low": [...]
  }
}
```

## Credits

- **Kris Araptus** - Original scanner and threat database
- **Jeremiah Coakley / FEDLIN** - Web UI and deep scanning feature

## License

MIT
