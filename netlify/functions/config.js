// netlify/functions/config.js
// Serves the Anthropic API key to the frontend securely
exports.handler = async () => {
  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      anthropicKey: process.env.ANTHROPIC_API_KEY || ""
    })
  };
};
