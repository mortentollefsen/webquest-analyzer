# WebQuest Analyzer

Dette er analysemotoren for WebQuest. Den bruker Playwright/Chromium, slik at nettsider analyseres etter at JavaScript har kjørt.

## Lokal test

```bash
npm install
npx playwright install chromium
npm start
```

Test:

```text
http://localhost:3000/analyze?command=headings&url=https://mortentollefsen.no/
```

## Hosting

Denne mappen kan legges i et GitHub-repo og hostes som en Docker-basert Web Service, for eksempel hos Render. Dockerfile bruker Microsofts offisielle Playwright-bilde, slik at Chromium og systemavhengigheter følger med.

Miljovariabel:

```text
ALLOWED_ORIGINS=https://mortentollefsen.no,https://www.mortentollefsen.no
OPENAI_API_KEY=<nøkkel for kommandoen Beskriv>
```

Når tjenesten er publisert, sett URL-en i `/apper/webquest/config.js`:

```js
window.WEBQUEST_CONFIG = {
  analyzerUrl: "https://DIN-TJENESTE.onrender.com/analyze",
};
```
