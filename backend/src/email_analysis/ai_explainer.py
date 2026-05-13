# backend/src/email_analysis/ai_explainer.py
# AI plain-English explanation of phishing results
# Member: Giovanni
#
# SIMPLE EXPLANATION:
# After analysis, we use AI to explain findings in simple language
# Most users don't understand technical terms like "SPF failed"
# The AI explanation tells them clearly: "This email is dangerous because..."
#
# TWO MODES:
# 1. OpenAI API - if API key is set, uses ChatGPT (best quality)
# 2. Fallback    - if no API key, uses built-in rule-based explanation

import os

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


def get_ai_explanation(risk_level, risk_score, reasons, subject, sender):
    """Generate plain-English explanation. Uses OpenAI or fallback."""
    api_key = os.getenv('OPENAI_API_KEY', '')

    # Use fallback if no valid API key
    if not api_key or api_key == 'your-openai-api-key-here' or not OPENAI_AVAILABLE:
        return _fallback_explanation(risk_level, risk_score, reasons)

    try:
        client = OpenAI(api_key=api_key)
        reasons_text = '\n'.join(f'- {r}' for r in reasons[:10]) if reasons else '- No indicators'

        # Ask ChatGPT to explain the findings simply
        prompt = f"""You are a cybersecurity expert explaining results to a non-technical user.

Email Analysis:
- Subject: {subject or 'Unknown'}
- Sender: {sender or 'Unknown'}
- Risk Level: {risk_level}
- Risk Score: {risk_score}/100
- Findings: {reasons_text}

Explain in 3 short points:
1. Is this email dangerous?
2. Why was it flagged?
3. What should the user do?

Keep under 150 words. Use simple language."""

        response = client.chat.completions.create(
            model='gpt-3.5-turbo',  # cheapest model
            messages=[
                {'role': 'system', 'content': 'You are a helpful cybersecurity assistant.'},
                {'role': 'user', 'content': prompt}
            ],
            max_tokens=250,  # limit to save API credits
            temperature=0.7,
        )
        return response.choices[0].message.content.strip()

    except Exception:
        return _fallback_explanation(risk_level, risk_score, reasons)


def _fallback_explanation(risk_level, risk_score, reasons):
    """Built-in explanation when OpenAI is not available."""
    if risk_level == 'RED':
        msg = (f"⚠️ HIGH RISK (score: {risk_score}/100) - This email is very likely a phishing attack. "
               "Do NOT click any links, open attachments or reply. Delete it immediately.")
    elif risk_level == 'YELLOW':
        msg = (f"⚡ SUSPICIOUS (score: {risk_score}/100) - This email has some phishing indicators. "
               "Be careful before clicking anything. Verify the sender first.")
    else:
        msg = (f"✅ SAFE (score: {risk_score}/100) - No major phishing indicators found. "
               "Standard caution still recommended - never share passwords via email.")

    # Add top 3 findings to explanation
    if reasons:
        top = reasons[:3]
        details = ' Key findings: ' + '; '.join(
            r.split('] ', 1)[-1] if ']' in r else r for r in top
        ) + '.'
        msg += details

    return msg
