exports.handler = async () => {
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    },
    body: JSON.stringify({
      anthropicKey: process.env.ANTHROPIC_API_KEY || "",
      openaiKey: process.env.OPENAI_API_KEY || ""
    })
  };
};
