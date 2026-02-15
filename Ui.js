/**
 * Email Security Scorer - UI Module
 * Builds the card-based UI for the Gmail Add-on
 */

/**
 * Create the homepage card (shown when clicking the add-on icon)
 */
function createHomepageCard() {
  var card = CardService.newCardBuilder();

  card.setHeader(CardService.newCardHeader()
    .setTitle("Email Security Scorer")
    .setSubtitle("System Active & Monitoring")
    .setImageStyle(CardService.ImageStyle.CIRCLE)
    .setImageUrl("https://img.icons8.com/color/96/000000/verified-account.png"));

  // HERO SECTION
  var heroSection = CardService.newCardSection();
  
  heroSection.addWidget(CardService.newDecoratedText()
    .setTopLabel("Current Status")
    .setText("<b>🛡️ Ready to Scan</b>")
    .setBottomLabel("Open an email to begin threat analysis")
    .setWrapText(true));

  card.addSection(heroSection);

  // FEATURES SECTION
  var featureSection = CardService.newCardSection()
    .setHeader("Active Modules");

  featureSection.addWidget(CardService.newDecoratedText()
    .setText("Smart Threat Detection")
    .setStartIcon(CardService.newIconImage().setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/bug_report_black_24dp.png")));

  featureSection.addWidget(CardService.newDecoratedText()
    .setText("URL & Attachment Scanning")
    .setStartIcon(CardService.newIconImage().setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/attachment_black_24dp.png")));

  featureSection.addWidget(CardService.newDecoratedText()
    .setText("SPF/DKIM Authentication")
    .setStartIcon(CardService.newIconImage().setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/verified_user_black_24dp.png")));

  card.addSection(featureSection);

  // ACTIONS SECTION
  var actionSection = CardService.newCardSection();
  
  var buttonSet = CardService.newButtonSet();

  buttonSet.addButton(CardService.newTextButton()
    .setText("✅ Whitelist")
    .setOnClickAction(CardService.newAction().setFunctionName("showWhitelistCard")));

  buttonSet.addButton(CardService.newTextButton()
    .setText("🚫 Blacklist")
    .setOnClickAction(CardService.newAction().setFunctionName("showBlacklistCard")));

  buttonSet.addButton(CardService.newTextButton()
    .setText("📋 History")
    .setOnClickAction(CardService.newAction().setFunctionName("showHistoryCard")));

  actionSection.addWidget(buttonSet);
  card.addSection(actionSection);

  return card.build();
}

/**
 * Create the results card showing analysis
 */
function createResultsCard(emailData, analysis) {
  var card = CardService.newCardBuilder();
  
  // DETERMINE COLOR & ICON BASED ON SCORE
  var headerIconUrl = "https://img.icons8.com/color/96/good-quality--v1.png";
  if(analysis.score >= 60) headerIconUrl = "https://img.icons8.com/color/96/high-priority.png";
  else if(analysis.score >= 30) headerIconUrl = "https://img.icons8.com/color/96/warning-shield.png";

  card.setHeader(CardService.newCardHeader()
    .setTitle(analysis.verdict.level.toUpperCase())
    .setSubtitle("Security Score: " + analysis.score + "/100")
    .setImageStyle(CardService.ImageStyle.CIRCLE)
    .setImageUrl(headerIconUrl));

  // VISUAL SCORE CARD
  var scoreSection = CardService.newCardSection();
  var scoreBar = createScoreBar(analysis.score); 
  
  scoreSection.addWidget(CardService.newDecoratedText()
    .setTopLabel("Threat Analysis Verdict")
    .setText("<b>" + analysis.verdict.description + "</b>")
    .setBottomLabel(scoreBar)
    .setWrapText(true));

  // ENGINE STATUS
  scoreSection.addWidget(CardService.newTextParagraph()
    .setText("<font color='#666666'><small>" + 
             (analysis.llmEnabled ? "🤖 AI Active" : "🤖 AI Off") + "  •  " + 
             (analysis.vtEnabled ? "🛡️ VT Active" : "🛡️ VT Off") + 
             "</small></font>"));
             
  card.addSection(scoreSection);

  // RISK SIGNALS
  var signalsSection = CardService.newCardSection().setHeader("Risk Factors");
  
  if (analysis.signals.length > 0) {
    var sortedSignals = analysis.signals.sort(function(a, b) {
      var severityOrder = { high: 0, medium: 1, low: 2, good: 3 };
      return (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4);
    });

    sortedSignals.forEach(function(signal) {
      var signalIconUrl = "";
      switch(signal.severity) {
        case "high": signalIconUrl = "https://www.gstatic.com/images/icons/material/system/1x/report_problem_black_24dp.png"; break;
        case "medium": signalIconUrl = "https://www.gstatic.com/images/icons/material/system/1x/warning_black_24dp.png"; break;
        case "low": signalIconUrl = "https://www.gstatic.com/images/icons/material/system/1x/info_black_24dp.png"; break;
        default: signalIconUrl = "https://www.gstatic.com/images/icons/material/system/1x/check_circle_black_24dp.png"; break;
      }

      var scoreImpact = signal.score > 0 ? " <font color='#dd2c00'>(+" + signal.score + " Risk)</font>" : 
                        signal.score < 0 ? " <font color='#0d904f'>(" + signal.score + " Risk)</font>" : "";

      signalsSection.addWidget(CardService.newDecoratedText()
        .setStartIcon(CardService.newIconImage().setIconUrl(signalIconUrl))
        .setTopLabel(signal.name)
        .setText(signal.description + scoreImpact)
        .setWrapText(true));
    });
  } else {
    signalsSection.addWidget(CardService.newDecoratedText()
        .setStartIcon(CardService.newIconImage().setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/check_circle_black_24dp.png"))
        .setText("No specific risk signals detected."));
  }
  card.addSection(signalsSection);

  // EMAIL METADATA
  var metaSection = CardService.newCardSection()
    .setCollapsible(true)
    .setHeader("Email Details");

  metaSection.addWidget(CardService.newDecoratedText()
    .setTopLabel("From")
    .setText(emailData.from)
    .setWrapText(true));

  var assetsSummary = (emailData.urls.length) + " Links • " + (emailData.attachments.length) + " Attachments";
  metaSection.addWidget(CardService.newTextParagraph().setText(assetsSummary));

  card.addSection(metaSection);

  // ACTION FOOTER
  var actionsSection = CardService.newCardSection();
  
  var actionButtons = CardService.newButtonSet();
  
  // Add to Whitelist button
  actionButtons.addButton(CardService.newTextButton()
    .setText("✅ Trust Sender")
    .setOnClickAction(CardService.newAction()
      .setFunctionName("addToWhitelist")
      .setParameters({
        email: emailData.senderEmail || "",
        domain: emailData.senderDomain || ""
      })));
  
  // Add to Blacklist button
  actionButtons.addButton(CardService.newTextButton()
    .setText("🚫 Block Sender")
    .setOnClickAction(CardService.newAction()
      .setFunctionName("addToBlacklist")
      .setParameters({
        email: emailData.senderEmail || "",
        domain: emailData.senderDomain || ""
      })));

  actionsSection.addWidget(actionButtons);
  card.addSection(actionsSection);
  
  // Save to history
  saveScanToHistory(emailData, analysis);

  return card.build();
}

/**
 * Create a visual score bar
 */
function createScoreBar(score) {
  var totalBlocks = 10;
  var filledBlocks = Math.round(score / 10);
  
  var filledChar = "🟩"; 
  if (score >= 40) filledChar = "🟨";
  if (score >= 70) filledChar = "🟥";
  
  var emptyChar = "⬜";

  var bar = "";
  for (var i = 0; i < filledBlocks; i++) bar += filledChar;
  for (var i = 0; i < (totalBlocks - filledBlocks); i++) bar += emptyChar;
  
  return bar; 
}

/**
 * Create error card
 */
function createErrorCard(message) {
  var card = CardService.newCardBuilder();
  
  card.setHeader(CardService.newCardHeader()
    .setTitle("❌ Error")
    .setSubtitle("Could not analyze email"));
  
  var section = CardService.newCardSection();
  section.addWidget(CardService.newTextParagraph().setText(message));
  
  card.addSection(section);
  
  return card.build();
}

/**
 * Show whitelist management card
 */
function showWhitelistCard() {
  var card = CardService.newCardBuilder();
  
  card.setHeader(CardService.newCardHeader()
    .setTitle("✅ Manage Whitelist")
    .setSubtitle("Trusted senders (reduced sensitivity)")
    .setImageStyle(CardService.ImageStyle.CIRCLE)
    .setImageUrl("https://img.icons8.com/color/96/checkmark--v1.png"));
  
  var whitelist = getWhitelist();
  
  // Info section
  var infoSection = CardService.newCardSection();
  infoSection.addWidget(CardService.newTextParagraph()
    .setText("<b>How it works:</b> Emails from whitelisted senders have reduced sensitivity for content-based checks. However, if scam content is detected, the whitelist protection is bypassed for safety."));
  card.addSection(infoSection);
  
  // User's trusted emails
  var emailSection = CardService.newCardSection()
    .setHeader("Your Trusted Emails");
  
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
    emailSection.addWidget(CardService.newTextParagraph()
      .setText("<i>No custom trusted emails added.</i>"));
  }
  
  // Add email input
  emailSection.addWidget(CardService.newTextInput()
    .setFieldName("newWhitelistEmail")
    .setTitle("Add trusted email")
    .setHint("e.g., boss@company.com"));
  
  emailSection.addWidget(CardService.newTextButton()
    .setText("➕ Add Email")
    .setOnClickAction(CardService.newAction()
      .setFunctionName("addEmailToWhitelist")));
  
  card.addSection(emailSection);
  
  // User's trusted domains
  var domainSection = CardService.newCardSection()
    .setHeader("Your Trusted Domains");
  
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
    domainSection.addWidget(CardService.newTextParagraph()
      .setText("<i>No custom trusted domains added.</i>"));
  }
  
  // Add domain input
  domainSection.addWidget(CardService.newTextInput()
    .setFieldName("newWhitelistDomain")
    .setTitle("Add trusted domain")
    .setHint("e.g., mycompany.com"));
  
  domainSection.addWidget(CardService.newTextButton()
    .setText("➕ Add Domain")
    .setOnClickAction(CardService.newAction()
      .setFunctionName("addDomainToWhitelist")));
  
  card.addSection(domainSection);
  
  // Built-in trusted domains (collapsible)
  var builtinSection = CardService.newCardSection()
    .setHeader("Built-in Trusted Domains")
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(1);
  
  builtinSection.addWidget(CardService.newTextParagraph()
    .setText("<i>These domains are trusted by default:</i>"));
  
  // Show a sample of built-in domains
  var sampleDomains = ['google.com', 'amazon.com', 'netflix.com', 'spotify.com', 'github.com', 'hoyoverse.com', 'steampowered.com', 'paypal.com'];
  builtinSection.addWidget(CardService.newTextParagraph()
    .setText(sampleDomains.join(', ') + ", and more..."));
  
  card.addSection(builtinSection);
  
  // Back button
  var navSection = CardService.newCardSection();
  navSection.addWidget(CardService.newTextButton()
    .setText("← Back to Home")
    .setOnClickAction(CardService.newAction().setFunctionName("onHomepage")));
  card.addSection(navSection);
  
  return CardService.newNavigation().pushCard(card.build());
}

/**
 * Show blacklist management card
 */
function showBlacklistCard() {
  var card = CardService.newCardBuilder();
  
  card.setHeader(CardService.newCardHeader()
    .setTitle("🚫 Manage Blacklist")
    .setSubtitle("Blocked senders (always flagged)")
    .setImageStyle(CardService.ImageStyle.CIRCLE)
    .setImageUrl("https://img.icons8.com/color/96/cancel--v1.png"));
  
  var blacklist = getBlacklist();
  
  // Emails section
  var emailSection = CardService.newCardSection()
    .setHeader("Blocked Emails");
  
  if (blacklist.emails.length > 0) {
    blacklist.emails.forEach(function(email) {
      emailSection.addWidget(CardService.newDecoratedText()
        .setText(email)
        .setStartIcon(CardService.newIconImage().setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/person_black_24dp.png"))
        .setButton(CardService.newImageButton()
          .setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/delete_black_24dp.png")
          .setAltText("Remove")
          .setOnClickAction(CardService.newAction()
            .setFunctionName("removeFromBlacklist")
            .setParameters({ type: "email", value: email }))));
    });
  } else {
    emailSection.addWidget(CardService.newTextParagraph()
      .setText("<i>No blocked emails.</i>"));
  }
  
  emailSection.addWidget(CardService.newTextInput()
    .setFieldName("newEmail")
    .setTitle("Add email to blacklist")
    .setHint("e.g., spammer@example.com"));
  
  emailSection.addWidget(CardService.newTextButton()
    .setText("➕ Add Email")
    .setOnClickAction(CardService.newAction()
      .setFunctionName("addEmailToBlacklist")));
  
  card.addSection(emailSection);
  
  // Domains section
  var domainSection = CardService.newCardSection()
    .setHeader("Blocked Domains");
  
  if (blacklist.domains.length > 0) {
    blacklist.domains.forEach(function(domain) {
      domainSection.addWidget(CardService.newDecoratedText()
        .setText(domain)
        .setStartIcon(CardService.newIconImage().setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/language_black_24dp.png"))
        .setButton(CardService.newImageButton()
          .setIconUrl("https://www.gstatic.com/images/icons/material/system/1x/delete_black_24dp.png")
          .setAltText("Remove")
          .setOnClickAction(CardService.newAction()
            .setFunctionName("removeFromBlacklist")
            .setParameters({ type: "domain", value: domain }))));
    });
  } else {
    domainSection.addWidget(CardService.newTextParagraph()
      .setText("<i>No blocked domains.</i>"));
  }
  
  domainSection.addWidget(CardService.newTextInput()
    .setFieldName("newDomain")
    .setTitle("Add domain to blacklist")
    .setHint("e.g., suspicious-domain.com"));
  
  domainSection.addWidget(CardService.newTextButton()
    .setText("➕ Add Domain")
    .setOnClickAction(CardService.newAction()
      .setFunctionName("addDomainToBlacklist")));
  
  card.addSection(domainSection);
  
  // Back button
  var navSection = CardService.newCardSection();
  navSection.addWidget(CardService.newTextButton()
    .setText("← Back to Home")
    .setOnClickAction(CardService.newAction().setFunctionName("onHomepage")));
  card.addSection(navSection);
  
  return CardService.newNavigation().pushCard(card.build());
}

/**
 * Show scan history card
 */
function showHistoryCard() {
  var card = CardService.newCardBuilder();
  
  card.setHeader(CardService.newCardHeader()
    .setTitle("📋 Scan History")
    .setSubtitle("Recent email analyses")
    .setImageStyle(CardService.ImageStyle.CIRCLE)
    .setImageUrl("https://img.icons8.com/color/96/time-machine--v1.png"));
  
  var history = getScanHistory();
  
  var historySection = CardService.newCardSection();
  
  if (history.length > 0) {
    history.slice(0, 10).forEach(function(scan) {
      var iconUrl = scan.verdict === "MALICIOUS" ? "https://img.icons8.com/color/48/high-priority.png" :
                    scan.verdict === "SUSPICIOUS" ? "https://img.icons8.com/color/48/warning-shield.png" :
                    scan.verdict === "CAUTION" ? "https://img.icons8.com/color/48/info--v1.png" : 
                    "https://img.icons8.com/color/48/good-quality--v1.png";
      
      historySection.addWidget(CardService.newDecoratedText()
        .setStartIcon(CardService.newIconImage().setIconUrl(iconUrl))
        .setTopLabel(scan.date)
        .setText("<b>" + scan.subject + "</b>")
        .setBottomLabel("From: " + scan.from + " | Score: " + scan.score)
        .setWrapText(true));
    });
  } else {
    historySection.addWidget(CardService.newTextParagraph()
      .setText("<i>No scan history yet. Open an email to analyze it.</i>"));
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
  
  return CardService.newNavigation().pushCard(card.build());
}