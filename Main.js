/**
 * Email Security Scorer - Gmail Add-on
 * Main entry point for the add-on
 */

/**
 * Homepage trigger - shows when user clicks the add-on icon
 */
function onHomepage(e) {
  return createHomepageCard();
}

/**
 * Contextual trigger - runs when user opens an email
 */
function onGmailMessage(e) {
  // Get the current message
  var messageId = e.gmail.messageId;
  var accessToken = e.gmail.accessToken;
  
  // Set up Gmail API access
  GmailApp.setCurrentMessageAccessToken(accessToken);
  var message = GmailApp.getMessageById(messageId);
  
  if (!message) {
    return createErrorCard("Could not access email message.");
  }
  
  // Extract email data for analysis
  var emailData = extractEmailData(message);
  
  // Analyze the email and get risk score
  var analysis = analyzeEmail(emailData);
  
  // Build and return the results card
  return createResultsCard(emailData, analysis);
}

/**
 * Extract relevant data from the email message
 */
function extractEmailData(message) {
  var from = message.getFrom();
  var subject = message.getSubject();
  var body = message.getPlainBody();
  var date = message.getDate();
  
  // Extract sender email from "Name <email>" format
  var senderEmail = extractEmail(from);
  var senderDomain = senderEmail ? senderEmail.split('@')[1] : 'unknown';
  
  // Get raw headers for deeper analysis
  var rawMessage = message.getRawContent();
  var headers = parseHeaders(rawMessage);
  
  // Extract URLs from body
  var urls = extractUrls(body);
  
  // Get attachment info
  var attachments = message.getAttachments();
  var attachmentInfo = attachments.map(function(att) {
    return {
      name: att.getName(),
      type: att.getContentType(),
      size: att.getSize()
    };
  });
  
  return {
    from: from,
    senderEmail: senderEmail,
    senderDomain: senderDomain,
    subject: subject,
    body: body,
    date: date,
    headers: headers,
    urls: urls,
    attachments: attachmentInfo,
    messageId: message.getId()
  };
}

/**
 * Extract email address from "Name <email>" format
 */
function extractEmail(fromField) {
  var match = fromField.match(/<(.+?)>/);
  if (match) {
    return match[1].toLowerCase();
  }
  // If no angle brackets, assume the whole thing is an email
  if (fromField.indexOf('@') !== -1) {
    return fromField.toLowerCase().trim();
  }
  return null;
}

/**
 * Parse email headers from raw message
 */
function parseHeaders(rawMessage) {
  var headers = {};
  var headerSection = rawMessage.split('\r\n\r\n')[0];
  var lines = headerSection.split('\r\n');
  
  var currentHeader = '';
  var currentValue = '';
  
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (line.match(/^\s+/)) {
      // Continuation of previous header
      currentValue += ' ' + line.trim();
    } else {
      // Save previous header
      if (currentHeader) {
        headers[currentHeader.toLowerCase()] = currentValue;
      }
      // Start new header
      var colonIndex = line.indexOf(':');
      if (colonIndex !== -1) {
        currentHeader = line.substring(0, colonIndex);
        currentValue = line.substring(colonIndex + 1).trim();
      }
    }
  }
  // Don't forget the last header
  if (currentHeader) {
    headers[currentHeader.toLowerCase()] = currentValue;
  }
  
  return headers;
}

/**
 * Extract URLs from email body
 */
function extractUrls(body) {
  if (!body) return [];
  var urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
  var matches = body.match(urlRegex);
  return matches ? matches : [];
}