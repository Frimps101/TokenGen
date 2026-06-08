# JWT Token Generator

A client-side JWT token generator that runs entirely in your browser. Build standard and custom claims, sign with HMAC (HS256/HS384/HS512), and copy the result — your secret key never leaves your device.

## Features

- Standard JWT claims: `iss`, `aud`, `exp`, `iat`, `nbf` (plus any custom claims like `sub`, `userId`, etc.)
- Dynamic custom claims (key-value pairs)
- HMAC signing: HS256, HS384, HS512
- Masked secret key with show/hide toggle
- Color-coded token output (header / payload / signature)
- One-click copy
- Decoded payload JSON view
- Input validation (empty secret, invalid dates, claim conflicts)

## Requirements

- Node.js 18+
- A modern browser with Web Crypto API support (Chrome, Firefox, Safari, Edge)

## Getting started

```bash
npm install
npm run dev
```

Open the URL shown in the terminal (typically `http://localhost:5173`).

## Build for production

```bash
npm run build
npm run preview
```

## Privacy

All token signing uses the browser's Web Crypto API. No network requests are made and no data is stored or transmitted.
