/**
 * Email Security Scorer - VirusTotal Integration
 * Scans URLs using VirusTotal API v3
 * 
 * Free tier: 4 requests per minute, 500 requests per day
 * Get your API key at: https://www.virustotal.com/gui/my-apikey
 */

// Get VirusTotal API key from Script Properties
function getVirusTotalKey() {
  var key = PropertiesService.getScriptProperties().getProperty('VIRUSTOTAL_API_KEY');
  if (!key) {
    Logger.log('VirusTotal API key not found in Script Properties');
    return null;
  }
  return key;
}

/**
 * Check a URL against VirusTotal
 * Returns: { safe: boolean, malicious: number, suspicious: number, clean: number, error: string }
 */
function checkUrlWithVirusTotal(url) {
  var apiKey = getVirusTotalKey();
  
  if (!apiKey) {
    return { enabled: false, error: 'API key not configured' };
  }
  
  try {
    // First, get the URL ID (base64 encoded URL without padding)
    var urlId = Utilities.base64Encode(url).replace(/=/g, '');
    
    // Try to get existing report first (doesn't cost extra if already scanned)
    var response = UrlFetchApp.fetch('https://www.virustotal.com/api/v3/urls/' + urlId, {
      method: 'get',
      headers: {
        'x-apikey': apiKey
      },
      muteHttpExceptions: true
    });
    
    var responseCode = response.getResponseCode();
    
    if (responseCode === 404) {
      // URL not in database, need to submit for scanning
      return submitUrlForScan(apiKey, url);
    }
    
    if (responseCode !== 200) {
      Logger.log('VirusTotal API error: ' + responseCode);
      return { enabled: false, error: 'API error: ' + responseCode };
    }
    
    var data = JSON.parse(response.getContentText());
    return parseVirusTotalResult(data);
    
  } catch (e) {
    Logger.log('VirusTotal error: ' + e.toString());
    return { enabled: false, error: e.toString() };
  }
}

/**
 * Submit a URL for scanning (if not already in database)
 */
function submitUrlForScan(apiKey, url) {
  try {
    var response = UrlFetchApp.fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'post',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      payload: 'url=' + encodeURIComponent(url),
      muteHttpExceptions: true
    });
    
    var responseCode = response.getResponseCode();
    
    if (responseCode !== 200) {
      return { enabled: false, error: 'Submit error: ' + responseCode };
    }
    
    // URL submitted, but we need to wait for analysis
    // For now, return unknown status
    return {
      enabled: true,
      status: 'pending',
      malicious: 0,
      suspicious: 0,
      clean: 0,
      undetected: 0,
      message: 'URL submitted for analysis'
    };
    
  } catch (e) {
    return { enabled: false, error: e.toString() };
  }
}

/**
 * Parse VirusTotal API response
 */
function parseVirusTotalResult(data) {
  try {
    var stats = data.data.attributes.last_analysis_stats;
    
    var malicious = stats.malicious || 0;
    var suspicious = stats.suspicious || 0;
    var clean = stats.harmless || 0;
    var undetected = stats.undetected || 0;
    var total = malicious + suspicious + clean + undetected;
    
    return {
      enabled: true,
      status: 'complete',
      malicious: malicious,
      suspicious: suspicious,
      clean: clean,
      undetected: undetected,
      total: total,
      // Calculate a threat score (0-100)
      threatScore: total > 0 ? Math.round((malicious * 100 + suspicious * 50) / total) : 0,
      url: data.data.attributes.url || '',
      lastAnalysis: data.data.attributes.last_analysis_date || ''
    };
    
  } catch (e) {
    Logger.log('Error parsing VT result: ' + e.toString());
    return { enabled: false, error: 'Parse error' };
  }
}

/**
 * Check multiple URLs (respects rate limit)
 * Only checks first 2 URLs to stay within rate limits
 */
function checkUrlsWithVirusTotal(urls) {
  var results = [];
  var apiKey = getVirusTotalKey();
  
  if (!apiKey) {
    return { enabled: false, results: [], error: 'API key not configured' };
  }
  
  // Only check first 2 URLs to avoid rate limiting
  var urlsToCheck = urls.slice(0, 2);
  
  for (var i = 0; i < urlsToCheck.length; i++) {
    var url = urlsToCheck[i];
    
    // Skip very long URLs or data URLs
    if (url.length > 2000 || url.indexOf('data:') === 0) {
      continue;
    }
    
    var result = checkUrlWithVirusTotal(url);
    result.url = url;
    results.push(result);
    
    // Small delay between requests to respect rate limit
    if (i < urlsToCheck.length - 1) {
      Utilities.sleep(500);
    }
  }
  
  return {
    enabled: true,
    results: results,
    checkedCount: results.length,
    totalUrls: urls.length
  };
}

/**
 * Convert VirusTotal results to scoring signals
 */
function virusTotalToSignals(vtResults) {
  var signals = [];
  
  if (!vtResults.enabled || !vtResults.results) {
    return signals;
  }
  
  var totalMalicious = 0;
  var totalSuspicious = 0;
  var allClean = true;
  var hasResults = false;
  
  vtResults.results.forEach(function(result) {
    if (result.enabled && result.status === 'complete') {
      hasResults = true;
      totalMalicious += result.malicious;
      totalSuspicious += result.suspicious;
      
      if (result.malicious > 0 || result.suspicious > 0) {
        allClean = false;
      }
    }
  });
  
  if (totalMalicious > 5) {
    // Multiple engines flagged as malicious - very bad
    signals.push({
      name: "🛡️ VirusTotal: Malicious URLs",
      description: totalMalicious + " security vendors flagged URL(s) as malicious",
      score: 40,
      severity: "high",
      isVirusTotal: true
    });
  } else if (totalMalicious > 0) {
    // Some engines flagged as malicious
    signals.push({
      name: "🛡️ VirusTotal: Suspicious URLs",
      description: totalMalicious + " security vendor(s) flagged URL(s) as potentially malicious",
      score: 25,
      severity: "medium",
      isVirusTotal: true
    });
  } else if (totalSuspicious > 0) {
    // Only suspicious, not malicious
    signals.push({
      name: "🛡️ VirusTotal: Caution",
      description: totalSuspicious + " security vendor(s) flagged URL(s) as suspicious",
      score: 10,
      severity: "low",
      isVirusTotal: true
    });
  } else if (allClean && hasResults) {
    // All URLs checked are clean - REDUCE score significantly
    signals.push({
      name: "🛡️ VirusTotal: Clean",
      description: "URL(s) verified clean by 70+ security vendors",
      score: -25,  // Increased reduction from -15 to -25
      severity: "good",
      isVirusTotal: true
    });
  }
  
  return signals;
}

/**
 * Test function - run manually to verify VirusTotal API
 */
function testVirusTotalAPI() {
  var key = getVirusTotalKey();
  
  if (!key) {
    Logger.log('❌ VIRUSTOTAL_API_KEY not found in Script Properties');
    Logger.log('');
    Logger.log('To set up:');
    Logger.log('1. Go to https://www.virustotal.com/gui/my-apikey');
    Logger.log('2. Copy your API key');
    Logger.log('3. In Apps Script: Project Settings > Script Properties');
    Logger.log('4. Add: VIRUSTOTAL_API_KEY = your-key');
    return;
  }
  
  Logger.log('✅ API Key found: ' + key.substring(0, 8) + '...');
  
  // Test with a known safe URL
  var testUrl = 'https://www.google.com';
  Logger.log('Testing URL: ' + testUrl);
  
  var result = checkUrlWithVirusTotal(testUrl);
  Logger.log('Result: ' + JSON.stringify(result, null, 2));
  
  if (result.enabled) {
    Logger.log('✅ VirusTotal API is working!');
    Logger.log('Malicious: ' + result.malicious);
    Logger.log('Suspicious: ' + result.suspicious);
    Logger.log('Clean: ' + result.clean);
  } else {
    Logger.log('❌ Error: ' + result.error);
  }
}