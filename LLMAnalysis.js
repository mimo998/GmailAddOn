/**
 * Email Security Scorer - LLM Analysis Module
 * Uses OpenRouter API for intelligent email analysis (supports free models)
 */

// Store your API key in Script Properties (more secure than hardcoding)
// Go to: Project Settings > Script Properties > Add: OPENROUTER_API_KEY = your-key
function getOpenRouterKey() {
  var key = PropertiesService.getScriptProperties().getProperty('OPENROUTER_API_KEY');
  if (!key) {
    Logger.log('OpenRouter API key not found in Script Properties');
    return null;
  }
  return key;
}

function analyzewithLLM(emailData) {
  var apiKey = getOpenRouterKey();
  
  if (!apiKey) {
    return {
      enabled: false,
      score: 0,
      flags: [],
      error: "API key not configured"
    };
  }
  
  // Prepare email content (truncate to save tokens)
  var bodySnippet = (emailData.body || '').substring(0, 800);
  var urlList = emailData.urls.slice(0, 3).join(', ');
  
  var prompt = 'Analyze this email and rate how likely it is to be a phishing/scam attempt.\n\n' +
    'From: ' + emailData.from + '\n' +
    'Subject: ' + (emailData.subject || '(no subject)') + '\n' +
    'Body: ' + bodySnippet + '\n' +
    'URLs: ' + (urlList || 'none') + '\n\n' +
    'IMPORTANT: Most emails are legitimate! Only flag as suspicious if there are CLEAR red flags like:\n' +
    '- Requests for passwords, credit cards, SSN\n' +
    '- Urgent threats about account suspension\n' +
    '- Suspicious links (IP addresses, misspelled domains)\n' +
    '- Too-good-to-be-true offers (free money, lottery wins)\n' +
    '- Sender mismatch (claims to be a bank but uses gmail)\n\n' +
    'Score guide:\n' +
    '0-10 = Normal email (newsletters, receipts, work emails)\n' +
    '10-30 = Slightly unusual but probably fine\n' +
    '30-60 = Some red flags, be careful\n' +
    '60-100 = Multiple clear phishing indicators\n\n' +
    'Respond ONLY with JSON:\n' +
    '{"score": <0-100>, "flags": ["flag1"], "summary": "<1 sentence>"}';

  // Try multiple models in case one is rate limited
  var models = [
    'arcee-ai/trinity-large-preview:free',
    'meta-llama/llama-4-maverick:free',
    'deepseek/deepseek-chat-v3-0324:free',
    'mistralai/mistral-small-3.1-24b-instruct:free',
    'nousresearch/deephermes-3-llama-3-8b-preview:free'
  ];
  
  for (var i = 0; i < models.length; i++) {
    var result = tryLLMCall(apiKey, models[i], prompt);
    if (result.success) {
      return result.data;
    }
    Logger.log('Model ' + models[i] + ' failed with code ' + result.statusCode + ', trying next...');
    // If rate limited (429) or not found (404), try next model
    if (result.statusCode !== 429 && result.statusCode !== 404) {
      break; // Other error, don't retry
    }
  }
  
  // All models failed
  return {
    enabled: false,
    score: 0,
    flags: [],
    error: "All models unavailable"
  };
}

/**
 * Helper function to make LLM API call
 */
function tryLLMCall(apiKey, model, prompt) {
  try {
    var response = UrlFetchApp.fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'post',
      headers: {
        'Authorization': 'Bearer ' + apiKey,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://gmail-security-scorer.app',
        'X-Title': 'Email Security Scorer'
      },
      payload: JSON.stringify({
        model: model,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ],
        max_tokens: 200,
        temperature: 0.2
      }),
      muteHttpExceptions: true
    });
    
    var responseCode = response.getResponseCode();
    var responseText = response.getContentText();
    
    if (responseCode !== 200) {
      return { success: false, statusCode: responseCode };
    }
    
    var json = JSON.parse(responseText);
    var content = json.choices[0].message.content.trim();
    
    // Clean up response - remove markdown, find JSON
    content = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    
    // Try to extract JSON if there's extra text
    var jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      content = jsonMatch[0];
    }
    
    var analysis = JSON.parse(content);
    
    return {
      success: true,
      data: {
        enabled: true,
        score: Math.min(100, Math.max(0, analysis.score || 0)),
        flags: analysis.flags || [],
        summary: analysis.summary || '',
        model: model,
        error: null
      }
    };
    
  } catch (e) {
    Logger.log('LLM exception (' + model + '): ' + e.toString());
    return { success: false, statusCode: 0 };
  }
}

/**
 * Convert LLM analysis to signals format
 */
function llmResultsToSignals(llmResult) {
  var signals = [];
  
  if (!llmResult.enabled || llmResult.error) {
    return signals;
  }
  
  // Add main LLM signal
  if (llmResult.score > 0) {
    var severity = llmResult.score >= 60 ? 'high' : 
                   llmResult.score >= 30 ? 'medium' : 'low';
    
    signals.push({
      name: "🤖 AI Analysis",
      description: llmResult.summary || ("AI detected suspicious patterns (score: " + llmResult.score + ")"),
      score: Math.round(llmResult.score * 0.4),  // Weight LLM at 40% of its score
      severity: severity,
      isLLM: true
    });
  }

  
  return signals;
}