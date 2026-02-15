/**
 * Email Security Scorer - Analysis Module
 * Contains all the logic for analyzing emails and calculating risk scores
 */

/**
 * Main analysis function - orchestrates all checks
 */
function analyzeEmail(emailData) {
  var signals = [];
  var totalScore = 0;
  var vtReduction = 0;  // Track VT reduction separately
  
  // 1. Check sender against blacklist
  var blacklistResult = checkBlacklist(emailData.senderEmail, emailData.senderDomain);
  if (blacklistResult.score > 0) {
    signals.push(blacklistResult);
    totalScore += blacklistResult.score;
  }
  
  // 2. Analyze email headers (SPF, DKIM, DMARC)
  var headerResults = analyzeHeaders(emailData.headers);
  headerResults.forEach(function(result) {
    signals.push(result);
    totalScore += result.score;
  });
  
  // 3. Check for suspicious patterns in subject/body
  var contentResults = analyzeContent(emailData.subject, emailData.body);
  contentResults.forEach(function(result) {
    signals.push(result);
    totalScore += result.score;
  });
  
  // 4. Analyze URLs
  var urlResults = analyzeUrls(emailData.urls);
  urlResults.forEach(function(result) {
    signals.push(result);
    totalScore += result.score;
  });
  
  // 5. Check attachments
  var attachmentResults = analyzeAttachments(emailData.attachments);
  attachmentResults.forEach(function(result) {
    signals.push(result);
    totalScore += result.score;
  });
  
  // 6. VirusTotal URL Check (if API key configured)
  var vtEnabled = false;
  try {
    if (emailData.urls && emailData.urls.length > 0) {
      var vtResults = checkUrlsWithVirusTotal(emailData.urls);
      if (vtResults && vtResults.enabled) {
        vtEnabled = true;
        var vtSignals = virusTotalToSignals(vtResults);
        vtSignals.forEach(function(result) {
          signals.push(result);
          // Track negative scores (reductions) separately
          if (result.score < 0) {
            vtReduction = result.score;  // e.g., -25 for clean
          } else {
            totalScore += result.score;
          }
        });
      }
    }
  } catch (e) {
    Logger.log('VirusTotal check failed: ' + e.toString());
  }
  
  // 7. LLM Analysis (if enabled)
  var llmResult = null;
  try {
    llmResult = analyzewithLLM(emailData);
    if (llmResult && llmResult.enabled) {
      var llmSignals = llmResultsToSignals(llmResult);
      llmSignals.forEach(function(result) {
        signals.push(result);
        totalScore += result.score;
      });
    }
  } catch (e) {
    Logger.log('LLM analysis failed: ' + e.toString());
  }
  
  // Cap positive scores at 100 FIRST
  totalScore = Math.min(100, totalScore);
  
  // THEN apply VirusTotal reduction (so clean URLs can reduce from 100 to 75)
  totalScore = totalScore + vtReduction;
  
  // Ensure minimum is 0
  totalScore = Math.max(0, totalScore);
  
  // Determine verdict
  var verdict = getVerdict(totalScore);
  
  return {
    score: totalScore,
    verdict: verdict,
    signals: signals,
    llmEnabled: llmResult ? llmResult.enabled : false,
    vtEnabled: vtEnabled
  };
}

/**
 * Check sender against user's blacklist
 */
function checkBlacklist(senderEmail, senderDomain) {
  var blacklist = getBlacklist();
  
  // Check exact email match
  if (blacklist.emails.indexOf(senderEmail) !== -1) {
    return {
      name: "Blacklisted Sender",
      description: "Sender email is on your blacklist",
      score: 50,
      severity: "high"
    };
  }
  
  // Check domain match
  if (blacklist.domains.indexOf(senderDomain) !== -1) {
    return {
      name: "Blacklisted Domain",
      description: "Sender domain is on your blacklist",
      score: 40,
      severity: "high"
    };
  }
  
  return { score: 0 };
}

/**
 * Analyze email authentication headers
 */
function analyzeHeaders(headers) {
  var results = [];
  
  // Check for Authentication-Results header
  var authResults = headers['authentication-results'] || '';
  
  // SPF Check
  if (authResults.indexOf('spf=fail') !== -1) {
    results.push({
      name: "SPF Failed",
      description: "Sender's server is not authorized to send for this domain",
      score: 25,
      severity: "high"
    });
  } else if (authResults.indexOf('spf=softfail') !== -1) {
    results.push({
      name: "SPF Soft Fail",
      description: "Sender's server authorization is questionable",
      score: 15,
      severity: "medium"
    });
  } else if (authResults.indexOf('spf=pass') !== -1) {
    results.push({
      name: "SPF Passed",
      description: "Sender's server is authorized",
      score: 0,
      severity: "good"
    });
  }
  
  // DKIM Check
  if (authResults.indexOf('dkim=fail') !== -1) {
    results.push({
      name: "DKIM Failed",
      description: "Email signature verification failed",
      score: 25,
      severity: "high"
    });
  } else if (authResults.indexOf('dkim=pass') !== -1) {
    results.push({
      name: "DKIM Passed",
      description: "Email signature verified",
      score: 0,
      severity: "good"
    });
  }
  
  // DMARC Check
  if (authResults.indexOf('dmarc=fail') !== -1) {
    results.push({
      name: "DMARC Failed",
      description: "Domain authentication policy check failed",
      score: 20,
      severity: "high"
    });
  } else if (authResults.indexOf('dmarc=pass') !== -1) {
    results.push({
      name: "DMARC Passed",
      description: "Domain authentication policy verified",
      score: 0,
      severity: "good"
    });
  }
  
  // Check for suspicious headers
  var receivedSpf = headers['received-spf'] || '';
  if (receivedSpf.toLowerCase().indexOf('fail') !== -1) {
    results.push({
      name: "Received-SPF Failed",
      description: "SPF validation failed at receiving server",
      score: 20,
      severity: "high"
    });
  }
  
  // Check X-Spam headers if present
  var spamStatus = headers['x-spam-status'] || '';
  if (spamStatus.toLowerCase().indexOf('yes') !== -1) {
    results.push({
      name: "Marked as Spam",
      description: "Email was flagged by spam filters",
      score: 15,
      severity: "medium"
    });
  }
  
  return results;
}

/**
 * Analyze email content for suspicious patterns
 */
function analyzeContent(subject, body) {
  var results = [];
  var text = ((subject || '') + ' ' + (body || '')).toLowerCase();
  var subjectLower = (subject || '').toLowerCase();
  
  // Urgency patterns (common in phishing)
  var urgencyPatterns = [
    'urgent', 'immediate action', 'act now', 'limited time',
    'expire', 'suspended', 'verify your account', 'confirm your identity',
    'unusual activity', 'unauthorized access', 'within 24 hours',
    'immediate', 'right away', 'don\'t wait', 'hurry'
  ];
  
  var urgencyCount = 0;
  urgencyPatterns.forEach(function(pattern) {
    if (text.indexOf(pattern) !== -1) urgencyCount++;
  });
  
  if (urgencyCount >= 3) {
    results.push({
      name: "High Urgency Language",
      description: "Multiple urgent phrases detected (common in phishing)",
      score: 20,
      severity: "medium"
    });
  } else if (urgencyCount >= 1) {
    results.push({
      name: "Urgency Language",
      description: "Urgency phrases detected",
      score: 10,
      severity: "low"
    });
  }
  
  // Financial/credential patterns
  var financialPatterns = [
    'password', 'credit card', 'social security', 'bank account',
    'login credentials', 'billing information', 'payment details',
    'wire transfer', 'bitcoin', 'cryptocurrency', 'ssn', 'pin code'
  ];
  
  var financialCount = 0;
  financialPatterns.forEach(function(pattern) {
    if (text.indexOf(pattern) !== -1) financialCount++;
  });
  
  if (financialCount >= 2) {
    results.push({
      name: "Sensitive Data Request",
      description: "Email requests sensitive financial/credential information",
      score: 25,
      severity: "high"
    });
  } else if (financialCount >= 1) {
    results.push({
      name: "Financial Reference",
      description: "Email mentions sensitive financial topics",
      score: 10,
      severity: "low"
    });
  }
  
  // FREE STUFF / PRIZE SCAM PATTERNS
  var scamPatterns = [
    'free', 'free gift card',
    'you won', 'you\'ve won', 'winner',
    'claim your prize', 'lottery', 'inheritance',
    'free money', 'get rich', 'make money fast',
    'nigerian prince', 'foreign prince', 'million dollars',
    'casino', 'betting', 'gambling','100% more', '100% free', '100% satisfied', 'additional income', 'be your own boss',
  ];
  
  var scamCount = 0;
  scamPatterns.forEach(function(pattern) {
    if (text.indexOf(pattern) !== -1) scamCount++;
  });
  
  if (scamCount == 1) {
    results.push({
      name: "Scam/Prize Pattern",
      description: "Common scam phrases detected (fake prizes, free currency, etc.)",
      score: 20,
      severity: "medium"
    });
  }
  if (scamCount > 1) {
    results.push({
      name: "Scam/Prize Pattern",
      description: "Common scam phrases detected (fake prizes, free currency, etc.)",
      score: 30,
      severity: "medium"
    });
  }
  
  // SUSPICIOUS SUBJECT LINE PATTERNS
  var suspiciousSubjectPatterns = [
    'not a virus', 'totally safe', 'trust me', 'this is real',
    'not spam', 'not a scam', 'legit', '100% real',
    'click here', 'open immediately', 'read this'
  ];
  
  var suspiciousSubject = suspiciousSubjectPatterns.some(function(pattern) {
    return subjectLower.indexOf(pattern) !== -1;
  });
  
  if (suspiciousSubject) {
    results.push({
      name: "Suspicious Subject Line",
      description: "Subject contains phrases often used ironically in scams",
      score: 25,
      severity: "high"
    });
  }
  
  // DOWNLOAD / INSTALL PROMPTS
  var downloadPatterns = [
    'download now', 'install now', 'click to download',
    'download for free', 'free download', 'get it now'
  ];
  
  var hasDownloadPrompt = downloadPatterns.some(function(pattern) {
    return text.indexOf(pattern) !== -1;
  });
  
  if (hasDownloadPrompt) {
    results.push({
      name: "Download Prompt",
      description: "Email prompts you to download something",
      score: 15,
      severity: "medium"
    });
  }
  
  // Check for executable mentions
  var execPatterns = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js'];
  var hasExec = execPatterns.some(function(ext) {
    return text.indexOf(ext) !== -1;
  });
  
  if (hasExec) {
    results.push({
      name: "Executable Reference",
      description: "Email mentions executable file types",
      score: 15,
      severity: "medium"
    });
  }
  
  return results;
}

/**
 * Analyze URLs in the email
 */
function analyzeUrls(urls) {
  var results = [];
  
  if (urls.length === 0) {
    return results;
  }
  
  // Trusted domains - don't flag these for HTTP or tracking
  var trustedDomains = [
    'gett.com', 'wolt.com', 'uber.com', 'bolt.eu', 'lyft.com',
    'google.com', 'gmail.com', 'youtube.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
    'amazon.com', 'amazon.co.il', 'ebay.com', 'aliexpress.com',
    'apple.com', 'microsoft.com', 'github.com', 'gitlab.com',
    'paypal.com', 'stripe.com',
    'netflix.com', 'spotify.com', 'disney.com',
    'bankhapoalim.co.il', 'leumi.co.il', 'mizrahi-tefahot.co.il', 'discount.co.il',
    'isracard.co.il', 'cal-online.co.il', 'max.co.il',
    'bezeq.co.il', 'partner.co.il', 'cellcom.co.il', 'hot.net.il',
    'super-pharm.co.il', 'shufersal.co.il',
    'gov.il', 'health.gov.il', 'tax.gov.il',
    'mailchimp.com', 'sendgrid.net', 'constantcontact.com',
    'zoom.us', 'slack.com', 'notion.so', 'dropbox.com',
    'university.edu', 'tau.ac.il', 'huji.ac.il', 'bgu.ac.il', 'technion.ac.il'
  ];
  
  // Check if URL belongs to a trusted domain
  function isTrustedUrl(url) {
    var urlLower = url.toLowerCase();
    for (var i = 0; i < trustedDomains.length; i++) {
      // Check if domain or subdomain matches
      if (urlLower.indexOf(trustedDomains[i]) !== -1) {
        return true;
      }
    }
    return false;
  }
  
  var suspiciousCount = 0;
  var ipUrlCount = 0;
  var shortenedCount = 0;
  var scamDomainCount = 0;
  var httpCount = 0;
  
  // URL shortener domains
  var shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'cutt.ly'];
  
  // Suspicious keywords in domains (only flag if NOT in trusted domain)
  var scamDomainKeywords = [
    'free-', '-free', 'giftcard', 'prize', 'winner', 'lottery',
    'login-', '-login', 'secure-', '-secure', 'verify-', '-verify',
    'account-', '-account', 'update-', '-update',
    'paypal-', 'amazon-', 'apple-', 'microsoft-', 'google-', 'facebook-'
  ];
  
  urls.forEach(function(url) {
    var urlLower = url.toLowerCase();
    var trusted = isTrustedUrl(urlLower);
    
    // Skip most checks for trusted domains
    if (trusted) {
      return; // continue to next URL
    }
    
    // Check for HTTP (not HTTPS) - only flag untrusted domains
    if (urlLower.indexOf('http://') === 0) {
      httpCount++;
    }
    
    // Check for IP-based URLs (always suspicious)
    if (urlLower.match(/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
      ipUrlCount++;
    }
    
    // Check for URL shorteners (mildly suspicious)
    shorteners.forEach(function(shortener) {
      if (urlLower.indexOf(shortener) !== -1) {
        shortenedCount++;
      }
    });
    
    // Check for scam keywords in domain
    scamDomainKeywords.forEach(function(keyword) {
      if (urlLower.indexOf(keyword) !== -1) {
        scamDomainCount++;
      }
    });
    
    // Check for suspicious patterns in URL
    var suspiciousUrlPatterns = [
      'login', 'signin', 'verify', 'secure', 'account', 'update',
      'confirm', 'banking', 'paypal', 'amazon'
    ];
    
    // Check if URL contains brand name but isn't the actual domain
    var brandMismatch = suspiciousUrlPatterns.some(function(pattern) {
      return urlLower.indexOf(pattern) !== -1 && 
             !urlLower.match(new RegExp('https?://[^/]*' + pattern + '\\.(com|org|net)'));
    });
    
    if (brandMismatch) {
      suspiciousCount++;
    }
  });
  
  if (ipUrlCount > 0) {
    results.push({
      name: "IP-based URLs",
      description: ipUrlCount + " URL(s) use IP addresses instead of domains",
      score: 25,
      severity: "high"
    });
  }
  
  if (httpCount > 0) {
    results.push({
      name: "Insecure HTTP Links",
      description: httpCount + " link(s) use HTTP instead of HTTPS",
      score: 15,
      severity: "medium"
    });
  }
  
  if (shortenedCount > 0) {
    results.push({
      name: "Shortened URLs",
      description: shortenedCount + " shortened URL(s) detected (hiding true destination)",
      score: 15,
      severity: "medium"
    });
  }
  
  if (scamDomainCount > 0) {
    results.push({
      name: "Suspicious Domain Keywords",
      description: "URL contains keywords commonly used in scam domains",
      score: 25,
      severity: "high"
    });
  }
  
  if (suspiciousCount > 0) {
    results.push({
      name: "Suspicious URLs",
      description: suspiciousCount + " URL(s) with suspicious patterns",
      score: 20,
      severity: "medium"
    });
  }
  
  return results;
}

/**
 * Analyze email attachments
 */
function analyzeAttachments(attachments) {
  var results = [];
  
  if (attachments.length === 0) {
    return results;
  }
  
  var dangerousTypes = [
    'application/x-msdownload',     // .exe
    'application/x-msdos-program',  // .exe
    'application/x-executable',
    'application/x-sh',             // shell script
    'application/x-javascript',
    'application/javascript',
    'application/x-bat',
    'application/x-msi',
    'application/vnd.ms-cab-compressed'
  ];
  
  var dangerousExtensions = [
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe',
    '.js', '.jse', '.ws', '.wsf', '.msi', '.msp', '.hta', '.cpl',
    '.ps1', '.reg', '.dll'
  ];
  
  var riskyExtensions = [
    '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm',  // Macro-enabled
    '.zip', '.rar', '.7z', '.tar', '.gz',  // Archives
    '.iso', '.img'  // Disk images
  ];
  
  var dangerousCount = 0;
  var riskyCount = 0;
  var macroCount = 0;
  
  attachments.forEach(function(att) {
    var name = String(att.name).toLowerCase();
    var type = String(att.type).toLowerCase();
    
    // Helper function since endsWith may not be available
    function strEndsWith(str, suffix) {
      return str.slice(-suffix.length) === suffix;
    }
    
    // Check dangerous types
    if (dangerousTypes.indexOf(type) !== -1) {
      dangerousCount++;
    }
    
    // Check dangerous extensions
    dangerousExtensions.forEach(function(ext) {
      if (strEndsWith(name, ext)) {
        dangerousCount++;
      }
    });
    
    // Check risky extensions
    riskyExtensions.forEach(function(ext) {
      if (strEndsWith(name, ext)) {
        riskyCount++;
      }
    });
    
    // Check for macro-enabled office docs
    if (name.match(/\.(docm|xlsm|pptm)$/)) {
      macroCount++;
    }
    
    // Check for double extensions (e.g., document.pdf.exe)
    if (name.match(/\.\w+\.\w+$/)) {
      var parts = name.split('.');
      var lastExt = '.' + parts[parts.length - 1];
      if (dangerousExtensions.indexOf(lastExt) !== -1) {
        dangerousCount++;
      }
    }
  });
  
  if (dangerousCount > 0) {
    results.push({
      name: "Dangerous Attachments",
      description: dangerousCount + " potentially dangerous file(s) attached",
      score: 35,
      severity: "high"
    });
  }
  
  if (macroCount > 0) {
    results.push({
      name: "Macro-Enabled Documents",
      description: macroCount + " macro-enabled Office document(s) attached",
      score: 25,
      severity: "high"
    });
  }
  
  if (riskyCount > 0 && dangerousCount === 0 && macroCount === 0) {
    results.push({
      name: "Risky Attachments",
      description: riskyCount + " attachment(s) that could contain hidden content",
      score: 10,
      severity: "low"
    });
  }
  
  return results;
}

/**
 * Convert score to verdict
 */
function getVerdict(score) {
  if (score >= 60) {
    return {
      level: "MALICIOUS",
      color: "#D93025",  // Red
      icon: "⛔",
      description: "This email shows strong indicators of being malicious. Exercise extreme caution."
    };
  } else if (score >= 30) {
    return {
      level: "SUSPICIOUS",
      color: "#F9AB00",  // Yellow/Orange
      icon: "⚠️",
      description: "This email has some concerning characteristics. Review carefully before taking any action."
    };
  } else if (score >= 10) {
    return {
      level: "CAUTION",
      color: "#1E88E5",  // Blue
      icon: "ℹ️",
      description: "Minor concerns detected. Likely safe but stay vigilant."
    };
  } else {
    return {
      level: "SAFE",
      color: "#34A853",  // Green
      icon: "✅",
      description: "No significant threats detected. Email appears safe."
    };
  }
}