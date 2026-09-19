/**
 * PhishGuard ML Engine
 * Based on PhishGuard ML static URL feature extraction & Random Forest decision rules
 * Reference: https://github.com/ishasonaria568-prog/phishguard-ml
 */

export interface PhishGuardAnalysis {
  url: string;
  normalizedUrl: string;
  classification: 'Safe' | 'Suspicious' | 'Phishing';
  riskScore: number; // 0 - 100
  disclaimer: string;
  features: {
    urlLength: number;
    hasIpAddress: boolean;
    isShortener: boolean;
    hasAtSymbol: boolean;
    doubleSlashRedirect: boolean;
    hasPrefixSuffix: boolean;
    subdomainsCount: number;
    isHttps: boolean;
    suspiciousTld: boolean;
    hasPort: boolean;
    httpsInDomain: boolean;
    sensitiveKeywordsFound: string[];
    hexEncodingCount: number;
  };
  reasons: string[];
  urlAnatomy: {
    protocol: string;
    domain: string;
    port: string;
    path: string;
    query: string;
  };
  mitreMapping?: {
    tactic: string;
    technique: string;
    id: string;
  };
}

const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly', 't.co', 'goo.gl',
  'rebrand.ly', 'cutt.ly', 'trib.al', 's.id', 'cli.re', 'bc.vc', 'adf.ly'
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'club', 'work', 'click', 'loan', 'gq', 'tk', 'ml', 'cf',
  'ga', 'buzz', 'stream', 'download', 'racing', 'win', 'men', 'accountant',
  'science', 'party', 'review', 'date', 'bid'
]);

const SENSITIVE_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'update', 'account', 'banking',
  'security', 'billing', 'support', 'paypal', 'apple', 'microsoft', 'google',
  'netflix', 'amazon', 'chase', 'wellsfargo', 'wallet', 'crypto', 'password',
  'credential', 'auth', 'recovery', 'secure', 'confirm', 'validation', 'ebay'
];

export function analyzeUrlWithPhishGuard(inputUrl: string): PhishGuardAnalysis {
  let raw = inputUrl.trim();
  if (!raw.startsWith('http://') && !raw.startsWith('https://')) {
    raw = 'http://' + raw;
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    // If URL parsing fails, create fallback dummy URL
    parsed = new URL('http://malformed-url-input.local');
  }

  const protocol = parsed.protocol.replace(':', '');
  const domain = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname;
  const search = parsed.search;
  const port = parsed.port;

  // 1. IP Address presence
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const hasIpAddress = ipv4Regex.test(domain);

  // 2. URL Length
  const urlLength = raw.length;

  // 3. Shortener detection
  const isShortener = SHORTENER_DOMAINS.has(domain);

  // 4. @ symbol
  const hasAtSymbol = raw.includes('@');

  // 5. Double slash redirection after protocol
  const restOfUrl = raw.substring(raw.indexOf('://') + 3);
  const doubleSlashRedirect = restOfUrl.includes('//');

  // 6. Hyphen / Prefix-Suffix in domain
  const hasPrefixSuffix = domain.includes('-');

  // 7. Subdomains count (e.g. login.secure.bank.com -> 3 dots)
  const dotParts = domain.split('.');
  const subdomainsCount = Math.max(0, dotParts.length - 2);

  // 8. HTTPS
  const isHttps = protocol === 'https';

  // 9. Suspicious TLD
  const tld = dotParts[dotParts.length - 1] || '';
  const suspiciousTld = SUSPICIOUS_TLDS.has(tld);

  // 10. Non-standard port
  const hasPort = port !== '' && port !== '80' && port !== '443';

  // 11. HTTPS token inside domain string
  const httpsInDomain = domain.includes('https') || domain.includes('http-');

  // 12. Sensitive keywords
  const fullText = (domain + pathname + search).toLowerCase();
  const sensitiveKeywordsFound = SENSITIVE_KEYWORDS.filter(kw => fullText.includes(kw));

  // 13. Hex / percentage encoding count
  const hexMatches = raw.match(/%[0-9A-Fa-f]{2}/g);
  const hexEncodingCount = hexMatches ? hexMatches.length : 0;

  // PhishGuard ML Random Forest Model Scoring Weight Simulation
  let score = 5; // Base minimum
  const reasons: string[] = [];

  if (hasIpAddress) {
    score += 35;
    reasons.push('Uses direct raw IP address instead of registered domain name.');
  }

  if (isShortener) {
    score += 25;
    reasons.push(`URL uses known shortening service (${domain}) to obfuscate target destination.`);
  }

  if (hasAtSymbol) {
    score += 25;
    reasons.push('Contains "@" character which can mislead browsers regarding authentic host.');
  }

  if (doubleSlashRedirect) {
    score += 25;
    reasons.push('Contains internal double slash ("//") redirection pattern.');
  }

  if (httpsInDomain) {
    score += 25;
    reasons.push('Deceptive "https" token embedded directly within hostname.');
  }

  if (suspiciousTld) {
    score += 20;
    reasons.push(`Domain registered under high-abuse Top Level Domain (.${tld}).`);
  }

  if (hasPrefixSuffix) {
    score += 12;
    reasons.push('Hostname contains hyphens typical of credential harvesting typosquatting.');
  }

  if (subdomainsCount >= 3) {
    score += 18;
    reasons.push(`Abnormal subdomain depth (${subdomainsCount} nested subdomains).`);
  } else if (subdomainsCount === 2) {
    score += 8;
  }

  if (urlLength > 75) {
    score += 15;
    reasons.push(`Excessive URL length (${urlLength} characters) exceeding standard threshold.`);
  } else if (urlLength > 54) {
    score += 6;
  }

  if (!isHttps) {
    score += 12;
    reasons.push('Transmitted over unencrypted HTTP protocol without transport security.');
  }

  if (sensitiveKeywordsFound.length > 0) {
    const kwWeight = Math.min(sensitiveKeywordsFound.length * 8, 28);
    score += kwWeight;
    reasons.push(`Contains high-risk credential keywords: [${sensitiveKeywordsFound.slice(0, 4).join(', ')}].`);
  }

  if (hexEncodingCount >= 3) {
    score += 12;
    reasons.push(`Significant percentage/hex encoding present (${hexEncodingCount} encoded tokens).`);
  }

  if (hasPort) {
    score += 10;
    reasons.push(`Explicit non-standard network port specified (:${port}).`);
  }

  // Bound score between 0 and 99
  const riskScore = Math.min(99, Math.max(1, score));

  // Determine Classification
  let classification: 'Safe' | 'Suspicious' | 'Phishing';
  if (riskScore >= 70) {
    classification = 'Phishing';
  } else if (riskScore >= 36) {
    classification = 'Suspicious';
  } else {
    classification = 'Safe';
    if (reasons.length === 0) {
      reasons.push('Standard domain structure with legitimate HTTPS certificate indicator and no deceptive patterns detected.');
    }
  }

  return {
    url: inputUrl,
    normalizedUrl: raw,
    classification,
    riskScore,
    disclaimer: 'ML assessment — investigate before taking action.',
    features: {
      urlLength,
      hasIpAddress,
      isShortener,
      hasAtSymbol,
      doubleSlashRedirect,
      hasPrefixSuffix,
      subdomainsCount,
      isHttps,
      suspiciousTld,
      hasPort,
      httpsInDomain,
      sensitiveKeywordsFound,
      hexEncodingCount
    },
    reasons,
    urlAnatomy: {
      protocol,
      domain,
      port: port || (protocol === 'https' ? '443' : '80'),
      path: pathname || '/',
      query: search || ''
    },
    mitreMapping: classification !== 'Safe' ? {
      tactic: 'Initial Access',
      technique: 'Phishing: Spearphishing Link',
      id: 'T1566.002'
    } : undefined
  };
}
