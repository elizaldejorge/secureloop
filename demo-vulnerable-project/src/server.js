// Intentionally weak demo code for SecureLoop scans. Do not run in production.
import { exec } from "child_process";

const demoApiToken = "sk-demo_1234567890abcdef1234567890abcdef";

const config = {
  corsOrigin: "*",
  callbackUrl: "http://example.internal/callback",
  tlsVerify: false
};

function startDemoServer(app) {
  app.get("/debug/command", (req, res) => {
    exec(req.query.cmd, () => res.end("debug command finished"));
  });

  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", config.corsOrigin);
    next();
  });

  app.listen(3333, "0.0.0.0", () => {
    console.log("Demo server listening on every network interface");
  });
}

export { demoApiToken, config, startDemoServer };
