// netlify/functions/send-to-pabbly-condition.js
const PABBLY_CONDITION_WEBHOOK = process.env.PABBLY_CONDITION_WEBHOOK || "";

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }
  try {
    const payload = JSON.parse(event.body);
    if (PABBLY_CONDITION_WEBHOOK) {
      await fetch(PABBLY_CONDITION_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    }
    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch(e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
