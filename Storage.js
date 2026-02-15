/**
 * Email Security Scorer - Storage Module
 * Handles persistent storage for blacklist, whitelist and scan history
 */

// Storage keys
var BLACKLIST_KEY = "user_blacklist";
var WHITELIST_KEY = "user_whitelist";
var HISTORY_KEY = "scan_history";
var MAX_HISTORY_ITEMS = 50;

// Built-in trusted domains (gaming, services, etc.)
var BUILTIN_TRUSTED_DOMAINS = [
  // Gaming
  'hoyoverse.com', 'mihoyo.com', 'e-mail.hoyoverse.com',
  'riotgames.com', 'leagueoflegends.com',
  'steampowered.com', 'store.steampowered.com',
  'epicgames.com', 'blizzard.com', 'battle.net',
  'playstation.com', 'xbox.com', 'nintendo.com',
  'ea.com', 'ubisoft.com',
  // Streaming
  'netflix.com', 'spotify.com', 'disney.com', 'hulu.com',
  'youtube.com', 'twitch.tv', 'primevideo.com',
  // Shopping
  'amazon.com', 'amazon.co.il', 'ebay.com', 'aliexpress.com',
  'wolt.com', 'gett.com', 'uber.com', 'bolt.eu',
  // Tech
  'google.com', 'gmail.com', 'apple.com', 'microsoft.com',
  'github.com', 'gitlab.com', 'linkedin.com',
  'dropbox.com', 'zoom.us', 'slack.com', 'notion.so',
  // Social
  'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
  'tiktok.com', 'reddit.com', 'discord.com',
  // Finance (Israeli)
  'bankhapoalim.co.il', 'leumi.co.il', 'mizrahi-tefahot.co.il',
  'discount.co.il', 'isracard.co.il', 'cal-online.co.il', 'max.co.il',
  'paypal.com', 'stripe.com',
  // Israeli services
  'bezeq.co.il', 'partner.co.il', 'cellcom.co.il', 'hot.net.il',
  'super-pharm.co.il', 'shufersal.co.il', 'gov.il',
  // Universities
  'tau.ac.il', 'huji.ac.il', 'technion.ac.il', 'weizmann.ac.il'
];

/**
 * Get the user's whitelist (combined with built-in)
 */
function getWhitelist() {
  var props = PropertiesService.getUserProperties();
  var stored = props.getProperty(WHITELIST_KEY);
  
  var userWhitelist = { emails: [], domains: [] };
  if (stored) {
    try {
      userWhitelist = JSON.parse(stored);
    } catch (e) {
      userWhitelist = { emails: [], domains: [] };
    }
  }
  
  // Combine user whitelist with built-in trusted domains
  var allDomains = BUILTIN_TRUSTED_DOMAINS.concat(userWhitelist.domains);
  
  return {
    emails: userWhitelist.emails,
    domains: allDomains,
    userDomains: userWhitelist.domains  // Track which ones user added
  };
}

/**
 * Save whitelist (only saves user-added entries)
 */
function saveWhitelist(whitelist) {
  var props = PropertiesService.getUserProperties();
  // Only save user-added entries, not built-in ones
  var toSave = {
    emails: whitelist.emails || [],
    domains: whitelist.userDomains || whitelist.domains || []
  };
  props.setProperty(WHITELIST_KEY, JSON.stringify(toSave));
}

/**
 * Check if sender is whitelisted
 */
function isWhitelisted(senderEmail, senderDomain) {
  var whitelist = getWhitelist();
  
  // Check exact email match
  if (senderEmail && whitelist.emails.indexOf(senderEmail.toLowerCase()) !== -1) {
    return true;
  }
  
  // Check domain match (including subdomains)
  if (senderDomain) {
    var domainLower = senderDomain.toLowerCase();
    for (var i = 0; i < whitelist.domains.length; i++) {
      var whitelistedDomain = whitelist.domains[i].toLowerCase();
      // Match exact domain or subdomain (e.g., e-mail.hoyoverse.com matches hoyoverse.com)
      if (domainLower === whitelistedDomain || domainLower.indexOf('.' + whitelistedDomain) !== -1) {
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Add sender to whitelist (from results card)
 */
function addToWhitelist(e) {
  var email = e.parameters.email;
  var domain = e.parameters.domain;
  var whitelist = getWhitelist();
  var messages = [];
  
  if (domain && whitelist.userDomains.indexOf(domain) === -1) {
    whitelist.userDomains.push(domain);
    messages.push("Added " + domain + " to whitelist");
  }
  
  saveWhitelist({
    emails: whitelist.emails,
    userDomains: whitelist.userDomains
  });
  
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification()
      .setText(messages.length > 0 ? messages.join(". ") : "Domain already in whitelist"))
    .build();
}

/**
 * Add email to whitelist (from management card)
 */
function addEmailToWhitelist(e) {
  var email = e.formInput.newWhitelistEmail;
  
  if (!email || email.trim() === "") {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Please enter an email address"))
      .build();
  }
  
  email = email.trim().toLowerCase();
  
  if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Invalid email format"))
      .build();
  }
  
  var whitelist = getWhitelist();
  
  if (whitelist.emails.indexOf(email) !== -1) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Email already in whitelist"))
      .build();
  }
  
  whitelist.emails.push(email);
  saveWhitelist({
    emails: whitelist.emails,
    userDomains: whitelist.userDomains
  });
  
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Added " + email + " to whitelist"))
    .setNavigation(CardService.newNavigation().updateCard(createWhitelistCardDirect()))
    .build();
}

/**
 * Add domain to whitelist (from management card)
 */
function addDomainToWhitelist(e) {
  var domain = e.formInput.newWhitelistDomain;
  
  if (!domain || domain.trim() === "") {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Please enter a domain"))
      .build();
  }
  
  domain = domain.trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  
  if (!domain.match(/^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/)) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Invalid domain format"))
      .build();
  }
  
  var whitelist = getWhitelist();
  
  if (whitelist.userDomains.indexOf(domain) !== -1) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Domain already in whitelist"))
      .build();
  }
  
  whitelist.userDomains.push(domain);
  saveWhitelist({
    emails: whitelist.emails,
    userDomains: whitelist.userDomains
  });
  
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Added " + domain + " to whitelist"))
    .setNavigation(CardService.newNavigation().updateCard(createWhitelistCardDirect()))
    .build();
}

/**
 * Remove from whitelist
 */
function removeFromWhitelist(e) {
  var type = e.parameters.type;
  var value = e.parameters.value;
  var whitelist = getWhitelist();
  
  if (type === "email") {
    var index = whitelist.emails.indexOf(value);
    if (index !== -1) {
      whitelist.emails.splice(index, 1);
    }
  } else if (type === "domain") {
    var index = whitelist.userDomains.indexOf(value);
    if (index !== -1) {
      whitelist.userDomains.splice(index, 1);
    }
  }
  
  saveWhitelist({
    emails: whitelist.emails,
    userDomains: whitelist.userDomains
  });
  
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Removed " + value + " from whitelist"))
    .setNavigation(CardService.newNavigation().updateCard(createWhitelistCardDirect()))
    .build();
}

/**
 * Helper to create whitelist card directly (for navigation refresh)
 */
function createWhitelistCardDirect() {
  var card = CardService.newCardBuilder();
  
  card.setHeader(CardService.newCardHeader()
    .setTitle("✅ Manage Whitelist")
    .setSubtitle("Trusted senders (reduced sensitivity)")
    .setImageStyle(CardService.ImageStyle.CIRCLE)
    .setImageUrl("https://img.icons8.com/color/96/checkmark--v1.png"));
  
  var whitelist = getWhitelist();
  
  var infoSection = CardService.newCardSection();
  infoSection.addWidget(CardService.newTextParagraph()
    .setText("<b>How it works:</b> Emails from whitelisted senders have reduced sensitivity. If scam content is detected, protection is bypassed."));
  card.addSection(infoSection);
  
  // User's trusted emails
  var emailSection = CardService.newCardSection().setHeader("Your Trusted Emails");
  
  if (whitelist.emails.length > 0) {
    whitelist.emails.forEach(function(email) {
      emailSection.addWidget(CardService.newDecoratedText()
        .setText(email)
        .setStartIcon(CardService.newIconImage().setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/person_black_24dp.png"))
        .setButton(CardService.newImageButton()
          .setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/delete_black_24dp.png")
          .setAltText("Remove")
          .setOnClickAction(CardService.newAction()
            .setFunctionName("removeFromWhitelist")
            .setParameters({ type: "email", value: email }))));
    });
  } else {
    emailSection.addWidget(CardService.newTextParagraph().setText("<i>No custom trusted emails.</i>"));
  }
  
  emailSection.addWidget(CardService.newTextInput()
    .setFieldName("newWhitelistEmail")
    .setTitle("Add trusted email"));
  emailSection.addWidget(CardService.newTextButton()
    .setText("➕ Add Email")
    .setOnClickAction(CardService.newAction().setFunctionName("addEmailToWhitelist")));
  card.addSection(emailSection);
  
  // User's trusted domains
  var domainSection = CardService.newCardSection().setHeader("Your Trusted Domains");
  
  if (whitelist.userDomains && whitelist.userDomains.length > 0) {
    whitelist.userDomains.forEach(function(domain) {
      domainSection.addWidget(CardService.newDecoratedText()
        .setText(domain)
        .setStartIcon(CardService.newIconImage().setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/language_black_24dp.png"))
        .setButton(CardService.newImageButton()
          .setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/delete_black_24dp.png")
          .setAltText("Remove")
          .setOnClickAction(CardService.newAction()
            .setFunctionName("removeFromWhitelist")
            .setParameters({ type: "domain", value: domain }))));
    });
  } else {
    domainSection.addWidget(CardService.newTextParagraph().setText("<i>No custom trusted domains.</i>"));
  }
  
  domainSection.addWidget(CardService.newTextInput()
    .setFieldName("newWhitelistDomain")
    .setTitle("Add trusted domain"));
  domainSection.addWidget(CardService.newTextButton()
    .setText("➕ Add Domain")
    .setOnClickAction(CardService.newAction().setFunctionName("addDomainToWhitelist")));
  card.addSection(domainSection);
  
  // Back button
  var navSection = CardService.newCardSection();
  navSection.addWidget(CardService.newTextButton()
    .setText("← Back to Home")
    .setOnClickAction(CardService.newAction().setFunctionName("onHomepage")));
  card.addSection(navSection);
  
  return card.build();
}

/**
 * Get the user's blacklist
 */
function getBlacklist() {
  var props = PropertiesService.getUserProperties();
  var stored = props.getProperty(BLACKLIST_KEY);
  
  if (stored) {
    try {
      return JSON.parse(stored);
    } catch (e) {
      // Reset if corrupted
      return { emails: [], domains: [] };
    }
  }
  
  return { emails: [], domains: [] };
}

/**
 * Save blacklist
 */
function saveBlacklist(blacklist) {
  var props = PropertiesService.getUserProperties();
  props.setProperty(BLACKLIST_KEY, JSON.stringify(blacklist));
}

/**
 * Add sender to blacklist (from results card)
 */
function addToBlacklist(e) {
  var email = e.parameters.email;
  var domain = e.parameters.domain;
  var blacklist = getBlacklist();
  var messages = [];
  
  if (email && blacklist.emails.indexOf(email) === -1) {
    blacklist.emails.push(email);
    messages.push("Added " + email + " to blacklist");
  }
  
  saveBlacklist(blacklist);
  
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification()
      .setText(messages.length > 0 ? messages.join(". ") : "Sender already in blacklist"))
    .build();
}

/**
 * Add email to blacklist (from management card)
 */
function addEmailToBlacklist(e) {
  var email = e.formInput.newEmail;
  
  if (!email || email.trim() === "") {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Please enter an email address"))
      .build();
  }
  
  email = email.trim().toLowerCase();
  
  // Basic email validation
  if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Invalid email format"))
      .build();
  }
  
  var blacklist = getBlacklist();
  
  if (blacklist.emails.indexOf(email) !== -1) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Email already in blacklist"))
      .build();
  }
  
  blacklist.emails.push(email);
  saveBlacklist(blacklist);
  
  // Refresh the card
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Added " + email + " to blacklist"))
    .setNavigation(CardService.newNavigation().popCard().pushCard(showBlacklistCard().getNavigation ? showBlacklistCard() : createBlacklistCardDirect()))
    .build();
}

/**
 * Add domain to blacklist (from management card)
 */
function addDomainToBlacklist(e) {
  var domain = e.formInput.newDomain;
  
  if (!domain || domain.trim() === "") {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Please enter a domain"))
      .build();
  }
  
  domain = domain.trim().toLowerCase();
  
  // Remove any protocol prefix
  domain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  
  // Basic domain validation
  if (!domain.match(/^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/)) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Invalid domain format"))
      .build();
  }
  
  var blacklist = getBlacklist();
  
  if (blacklist.domains.indexOf(domain) !== -1) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Domain already in blacklist"))
      .build();
  }
  
  blacklist.domains.push(domain);
  saveBlacklist(blacklist);
  
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Added " + domain + " to blacklist"))
    .setNavigation(CardService.newNavigation().updateCard(createBlacklistCardDirect()))
    .build();
}

/**
 * Remove from blacklist
 */
function removeFromBlacklist(e) {
  var type = e.parameters.type;
  var value = e.parameters.value;
  var blacklist = getBlacklist();
  
  if (type === "email") {
    var index = blacklist.emails.indexOf(value);
    if (index !== -1) {
      blacklist.emails.splice(index, 1);
    }
  } else if (type === "domain") {
    var index = blacklist.domains.indexOf(value);
    if (index !== -1) {
      blacklist.domains.splice(index, 1);
    }
  }
  
  saveBlacklist(blacklist);
  
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Removed " + value + " from blacklist"))
    .setNavigation(CardService.newNavigation().updateCard(createBlacklistCardDirect()))
    .build();
}

/**
 * Helper to create blacklist card directly (for navigation)
 */
function createBlacklistCardDirect() {
  var card = CardService.newCardBuilder();
  
  card.setHeader(CardService.newCardHeader()
    .setTitle("⚙️ Manage Blacklist")
    .setSubtitle("Configure blocked senders"));
  
  var blacklist = getBlacklist();
  
  // Emails section
  var emailSection = CardService.newCardSection()
    .setHeader("Blocked Emails");
  
  if (blacklist.emails.length > 0) {
    blacklist.emails.forEach(function(email) {
      emailSection.addWidget(CardService.newDecoratedText()
        .setText(email)
        .setButton(CardService.newImageButton()
          .setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/delete_black_24dp.png")
          .setAltText("Remove")
          .setOnClickAction(CardService.newAction()
            .setFunctionName("removeFromBlacklist")
            .setParameters({ type: "email", value: email }))));
    });
  } else {
    emailSection.addWidget(CardService.newTextParagraph()
      .setText("No blocked emails."));
  }
  
  emailSection.addWidget(CardService.newTextInput()
    .setFieldName("newEmail")
    .setTitle("Add email to blacklist"));
  
  emailSection.addWidget(CardService.newTextButton()
    .setText("Add Email")
    .setOnClickAction(CardService.newAction().setFunctionName("addEmailToBlacklist")));
  
  card.addSection(emailSection);
  
  // Domains section
  var domainSection = CardService.newCardSection()
    .setHeader("Blocked Domains");
  
  if (blacklist.domains.length > 0) {
    blacklist.domains.forEach(function(domain) {
      domainSection.addWidget(CardService.newDecoratedText()
        .setText(domain)
        .setButton(CardService.newImageButton()
          .setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/delete_black_24dp.png")
          .setAltText("Remove")
          .setOnClickAction(CardService.newAction()
            .setFunctionName("removeFromBlacklist")
            .setParameters({ type: "domain", value: domain }))));
    });
  } else {
    domainSection.addWidget(CardService.newTextParagraph()
      .setText("No blocked domains."));
  }
  
  domainSection.addWidget(CardService.newTextInput()
    .setFieldName("newDomain")
    .setTitle("Add domain to blacklist"));
  
  domainSection.addWidget(CardService.newTextButton()
    .setText("Add Domain")
    .setOnClickAction(CardService.newAction().setFunctionName("addDomainToBlacklist")));
  
  card.addSection(domainSection);
  
  // Back button
  var navSection = CardService.newCardSection();
  navSection.addWidget(CardService.newTextButton()
    .setText("← Back to Home")
    .setOnClickAction(CardService.newAction().setFunctionName("onHomepage")));
  card.addSection(navSection);
  
  return card.build();
}

/**
 * Get scan history
 */
function getScanHistory() {
  var props = PropertiesService.getUserProperties();
  var stored = props.getProperty(HISTORY_KEY);
  
  if (stored) {
    try {
      return JSON.parse(stored);
    } catch (e) {
      return [];
    }
  }
  
  return [];
}

/**
 * Save scan to history
 */
function saveScanToHistory(emailData, analysis) {
  var history = getScanHistory();
  
  var entry = {
    date: new Date().toLocaleString(),
    from: emailData.senderEmail || emailData.from,
    subject: emailData.subject || "(No subject)",
    score: analysis.score,
    verdict: analysis.verdict.level,
    messageId: emailData.messageId
  };
  
  // Add to beginning
  history.unshift(entry);
  
  // Trim to max size
  if (history.length > MAX_HISTORY_ITEMS) {
    history = history.slice(0, MAX_HISTORY_ITEMS);
  }
  
  var props = PropertiesService.getUserProperties();
  props.setProperty(HISTORY_KEY, JSON.stringify(history));
}

/**
 * Clear scan history
 */
function clearHistory() {
  var props = PropertiesService.getUserProperties();
  props.deleteProperty(HISTORY_KEY);
  
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("History cleared"))
    .setNavigation(CardService.newNavigation().updateCard(createHistoryCardDirect()))
    .build();
}

/**
 * Helper to create history card directly
 */
function createHistoryCardDirect() {
  var card = CardService.newCardBuilder();
  
  card.setHeader(CardService.newCardHeader()
    .setTitle("📋 Scan History")
    .setSubtitle("Recent email analyses"));
  
  var history = getScanHistory();
  
  var historySection = CardService.newCardSection();
  
  if (history.length > 0) {
    history.slice(0, 10).forEach(function(scan) {
      var icon = scan.verdict === "MALICIOUS" ? "🔴" :
                 scan.verdict === "SUSPICIOUS" ? "🟡" :
                 scan.verdict === "CAUTION" ? "🔵" : "🟢";
      
      historySection.addWidget(CardService.newDecoratedText()
        .setTopLabel(scan.date)
        .setText(icon + " " + scan.subject)
        .setBottomLabel("From: " + scan.from + " | Score: " + scan.score)
        .setWrapText(true));
    });
  } else {
    historySection.addWidget(CardService.newTextParagraph()
      .setText("No scan history yet."));
  }
  
  card.addSection(historySection);
  
  if (history.length > 0) {
    var clearSection = CardService.newCardSection();
    clearSection.addWidget(CardService.newTextButton()
      .setText("🗑️ Clear History")
      .setOnClickAction(CardService.newAction().setFunctionName("clearHistory")));
    card.addSection(clearSection);
  }
  
  var navSection = CardService.newCardSection();
  navSection.addWidget(CardService.newTextButton()
    .setText("← Back to Home")
    .setOnClickAction(CardService.newAction().setFunctionName("onHomepage")));
  card.addSection(navSection);
  
  return card.build();
}