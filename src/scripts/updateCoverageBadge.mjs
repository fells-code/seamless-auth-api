import fs from 'node:fs';
import path from 'node:path';

const repoRoot = process.cwd();
const coverageSummaryPath = path.join(repoRoot, 'coverage', 'coverage-summary.json');
const badgePath = path.join(repoRoot, 'resources', 'coverage-badge.svg');
const readmePath = path.join(repoRoot, 'README.md');

if (!fs.existsSync(coverageSummaryPath)) {
  throw new Error(
    'coverage/coverage-summary.json was not found. Run `npm run coverage` before generating the badge.',
  );
}

const summary = JSON.parse(fs.readFileSync(coverageSummaryPath, 'utf8'));
const totalCoverage = summary?.total?.lines?.pct;

if (typeof totalCoverage !== 'number' || Number.isNaN(totalCoverage)) {
  throw new Error('Unable to read total line coverage from coverage/coverage-summary.json.');
}

const normalizedCoverage = Number(totalCoverage.toFixed(1));
const coverageLabel = `${normalizedCoverage}%`;
const badgeColor = getCoverageColor(normalizedCoverage);
const svg = buildBadgeSvg('coverage', coverageLabel, badgeColor);

fs.mkdirSync(path.dirname(badgePath), { recursive: true });
fs.writeFileSync(badgePath, `${svg}\n`);

const readme = fs.readFileSync(readmePath, 'utf8');
const badgeLine = `![coverage](resources/coverage-badge.svg)`;

if (
  !readme.includes('[![codecov](') &&
  !readme.includes('![coverage](resources/coverage-badge.svg)')
) {
  throw new Error('README.md does not contain the expected coverage badge line.');
}

const nextReadme = readme.replace(/\[!\[(?:codecov|coverage)\][^\n]+\n/, `${badgeLine}\n`);

fs.writeFileSync(readmePath, nextReadme);

function getCoverageColor(coverage) {
  if (coverage >= 90) return '#2ea043';
  if (coverage >= 80) return '#4c1';
  if (coverage >= 70) return '#97ca00';
  if (coverage >= 60) return '#dfb317';
  if (coverage >= 50) return '#fe7d37';
  return '#e05d44';
}

function buildBadgeSvg(label, value, color) {
  const labelWidth = getTextWidth(label);
  const valueWidth = getTextWidth(value);
  const totalWidth = labelWidth + valueWidth;
  const valueX = labelWidth + valueWidth / 2;
  const labelX = labelWidth / 2;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${value}">
  <title>${label}: ${value}</title>
  <linearGradient id="smooth" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".7"/>
    <stop offset=".1" stop-color="#aaa" stop-opacity=".1"/>
    <stop offset=".9" stop-color="#000" stop-opacity=".3"/>
    <stop offset="1" stop-color="#000" stop-opacity=".5"/>
  </linearGradient>
  <clipPath id="round">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#round)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#smooth)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${labelX}" y="15" fill="#010101" fill-opacity=".3">${label}</text>
    <text x="${labelX}" y="14">${label}</text>
    <text x="${valueX}" y="15" fill="#010101" fill-opacity=".3">${value}</text>
    <text x="${valueX}" y="14">${value}</text>
  </g>
</svg>`;
}

function getTextWidth(text) {
  return text.length * 7 + 10;
}
