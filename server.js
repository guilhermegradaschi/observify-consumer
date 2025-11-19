const http = require("node:http");
const { handler } = require("./metrics-consumer");

const PORT = Number(process.env.PORT || 3000);

const server = http.createServer((req, res) => {
  if (!req.url) {
    res.statusCode = 400;
    res.end("Bad request");
    return;
  }

  if (req.method !== "POST" || req.url !== "/metrics") {
    res.statusCode = 404;
    res.end("Not found");
    return;
  }

  const chunks = [];

  req.on("data", (chunk) => {
    chunks.push(chunk);
  });

  req.on("end", async () => {
    const bodyBuf = Buffer.concat(chunks);

    const event = {
      httpMethod: req.method,
      headers: req.headers,
      body: bodyBuf.toString("utf8"),
      isBase64Encoded: false,
      path: req.url,
    };

    try {
      const result = await handler(event);
      res.statusCode = result.statusCode || 200;
      res.setHeader("content-type", "application/json");
      res.end(result.body || "");
    } catch (e) {
      console.error("handler error", e);
      res.statusCode = 500;
      res.setHeader("content-type", "application/json");
      res.end('{"message":"Internal server error"}');
    }
  });
});

server.listen(PORT, () => {
  console.log(`metrics consumer listening on :${PORT}`);
});
