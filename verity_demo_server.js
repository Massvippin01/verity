const http = require('http');
const PORT = 8080;

const server = http.createServer((req, res) => {
  console.log(`[DEMO :8080] ${req.url}`);

  // ═══════════════════════════════════════════════════════════════════════════
  // DOWNLOAD ENDPOINT — Malicious APK payload
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/download-file' || req.url === '/downloads/sbi_yono_rewards.apk') {
    const totalBytes = 5 * 1024 * 1024; // 5 MB realistic APK size
    const chunkSize = 64 * 1024; // 64 KB per chunk
    const dummyChunk = Buffer.alloc(chunkSize, 0x50);
    dummyChunk.write('PK\x03\x04verity_sbi_yono_malicious_apk_payload', 0);

    res.writeHead(200, {
      'Content-Type': 'application/vnd.android.package-archive',
      'Content-Disposition': 'attachment; filename="sbi_yono_rewards.apk"',
      'Content-Length': totalBytes,
      'Accept-Ranges': 'bytes'
    });

    let sentBytes = 0;
    let timer = null;

    const cleanup = () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    };

    req.on('close', cleanup);
    res.on('close', cleanup);
    res.on('error', cleanup);

    // Send first chunk immediately so Chrome receives headers, creates download, and determines filename
    res.write(dummyChunk);
    sentBytes += chunkSize;

    // Stream remaining chunks spaced out to give Chrome active in-progress state for pause
    timer = setInterval(() => {
      if (res.writableEnded || res.destroyed || req.destroyed) {
        cleanup();
        return;
      }
      if (sentBytes < totalBytes) {
        const toSend = Math.min(chunkSize, totalBytes - sentBytes);
        res.write(dummyChunk.subarray(0, toSend));
        sentBytes += toSend;
      } else {
        cleanup();
        res.end();
      }
    }, 150);

    return;
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO A — Fake Bank Login (Plain HTML, no embedded overlays)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/bank') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>HDFC NetBanking - Secure Login</title>
<style>
  body{font-family:Arial,sans-serif;background:#f4f6f9;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .box{background:#fff;padding:40px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.1);width:350px;text-align:center;border-top:5px solid #004c8f}
  .logo{font-size:24px;font-weight:bold;color:#004c8f;margin-bottom:20px}
  input{width:100%;padding:12px;margin:10px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
  button{width:100%;padding:12px;background:#004c8f;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px;font-weight:bold;margin-top:10px}
</style></head><body>
<div class="box">
  <div class="logo">HDFC Bank NetBanking</div>
  <p style="color:#666;font-size:14px">Welcome to HDFC Bank secure net banking login.</p>
  <form><input type="text" placeholder="Customer ID"><input type="password" placeholder="IPIN (Password)"><input type="text" placeholder="OTP"><button type="button">SECURE LOGIN</button></form>
  <p style="font-size:11px;color:#999;margin-top:15px">HDFC Bank Limited.</p>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO CSP — Strict CSP Test Page (font-src 'none')
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/csp-test') {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Content-Security-Policy': "default-src 'self'; font-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    });
    return res.end(`<!DOCTYPE html><html><head><title>HDFC NetBanking - Strict CSP</title>
<style>
  body{font-family:Arial,sans-serif;background:#f4f6f9;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .box{background:#fff;padding:40px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.1);width:350px;text-align:center;border-top:5px solid #004c8f}
  .logo{font-size:24px;font-weight:bold;color:#004c8f;margin-bottom:20px}
  input{width:100%;padding:12px;margin:10px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
  button{width:100%;padding:12px;background:#004c8f;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px;font-weight:bold;margin-top:10px}
</style></head><body>
<div class="box">
  <div class="logo">HDFC Bank NetBanking</div>
  <p style="color:#666;font-size:14px">Welcome to HDFC Bank secure net banking login.</p>
  <form><input type="text" placeholder="Customer ID"><input type="password" placeholder="IPIN (Password)"><input type="text" placeholder="OTP"><button type="button">SECURE LOGIN</button></form>
  <p style="font-size:11px;color:#999;margin-top:15px">HDFC Bank Limited.</p>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO GOOGLE SEARCH — Real Google DOM & Styling for Search Engine Testing
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url.startsWith('/demo/google-search')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>hdfc netbanking - Google Search</title>
<style>
  body { font-family: Roboto, arial, sans-serif; background: #fff; color: #202124; margin: 0; padding: 24px 40px; }
  body.dark-mode { background: #202124 !important; color: #bdc1c6 !important; }
  body.dark-mode h3 { color: #8ab4f8 !important; }
  body.dark-mode .cite { color: #bdc1c6 !important; }
  body.dark-mode .snippet { color: #9aa0a6 !important; }
  #search { max-width: 652px; }
  .g { margin-bottom: 28px; }
  h3 { font-size: 20px; line-height: 26px; margin: 0 0 4px 0; font-weight: 400; color: #1a0dab; }
  a { text-decoration: none; color: inherit; }
  a:hover h3 { text-decoration: underline; }
  .cite { font-size: 14px; line-height: 1.3; color: #202124; margin-bottom: 4px; }
  .snippet { font-size: 14px; line-height: 1.58; color: #4d5156; }
</style></head><body>
<div id="search">
  <div id="rso">
    <div class="g">
      <div class="cite">https://netbanking.hdfcbank.com &gt; netbanking</div>
      <a href="https://netbanking.hdfcbank.com/netbanking/">
        <h3>Welcome to HDFC Bank NetBanking</h3>
      </a>
      <div class="snippet">Login to HDFC Bank NetBanking for secure online banking services, fund transfer, bill payments and more.</div>
    </div>
    <div class="g">
      <div class="cite">https://free-movies-online.click &gt; watch</div>
      <a href="https://free-movies-online.click/watch/stream">
        <h3>Watch Free Movies HD 2026 - Stream Online Free</h3>
      </a>
      <div class="snippet">Stream latest high definition movies online without registration. High speed servers.</div>
    </div>
    <div class="g">
      <div class="cite">https://hdfc-bank-netbanking-verify.xyz &gt; urgent</div>
      <a href="https://hdfc-bank-netbanking-verify.xyz/urgent-kyc">
        <h3>HDFC Bank KYC Update Mandatory - Complete NetBanking Verification</h3>
      </a>
      <div class="snippet">Dear customer, your netbanking access will be suspended within 24 hours. Verify now.</div>
    </div>
  </div>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO B — Fake Payment Gateway (Plain HTML, no embedded overlays)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/payment') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>PayPal Secure Checkout</title>
<style>
  body{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;background:#f5f7fa;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .box{background:#fff;padding:40px;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.1);width:400px;text-align:center}
  .logo{font-size:28px;font-weight:bold;color:#003087;font-style:italic}.logo span{color:#009cde}
  .amount{font-size:32px;color:#333;font-weight:300;margin-bottom:30px}
  .grp{text-align:left;margin-bottom:15px}
  label{font-size:13px;color:#666;font-weight:bold;display:block;margin-bottom:5px}
  input{width:100%;padding:12px;border:1px solid #ccc;border-radius:6px;box-sizing:border-box;font-size:14px}
  .row{display:flex;gap:15px}.row .grp{flex:1}
  button{width:100%;padding:14px;background:#0070ba;color:#fff;border:none;border-radius:24px;cursor:pointer;font-size:16px;font-weight:bold;margin-top:20px}
</style></head><body>
<div class="box">
  <div class="logo">Pay<span>Pal</span></div>
  <p style="color:#666;font-size:14px">Complete your purchase</p>
  <div class="amount">$299.99 USD</div>
  <form>
    <div class="grp"><label>Card Number</label><input placeholder="1234 5678 9012 3456"></div>
    <div class="row"><div class="grp"><label>Expiry</label><input placeholder="MM/YY"></div><div class="grp"><label>CVV</label><input placeholder="123"></div></div>
    <div class="grp"><label>OTP Verification</label><input placeholder="Enter OTP"></div>
    <button type="button">Pay Now</button>
  </form>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO C — UPI Cashback Scam (Plain HTML, no embedded overlays)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/upi') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>Paytm - Claim Your Cashback</title>
<style>
  body{font-family:Arial,sans-serif;background:#0f172a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .card{background:#1e293b;padding:40px;border-radius:16px;border:1px solid #334155;text-align:center;width:350px;box-shadow:0 15px 35px rgba(0,0,0,.5)}
  .amount{font-size:42px;font-weight:bold;color:#4ade80;margin:20px 0}
  .btn{display:inline-block;width:100%;padding:16px;background:#0ea5e9;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;font-size:18px;margin-top:20px;box-sizing:border-box;text-align:center}
</style></head><body>
<div class="card">
  <h2 style="margin-top:0;color:#38bdf8">Paytm Rewards</h2>
  <p style="color:#94a3b8">Congratulations! You have won a cashback reward.</p>
  <div class="amount">₹5,000</div>
  <p style="font-size:13px;color:#64748b">Click below to receive money to your bank account.</p>
  <a class="btn" href="upi://pay?pa=claimreward@fakeupi&pn=PaytmReward&am=5000&cu=INR">Claim ₹5,000 Cashback Now</a>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO D — Digital Arrest / Utility Scam (Plain HTML, no embedded overlays)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/utility') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>Electricity Board — Urgent Notice</title>
<style>
  body{font-family:Arial,sans-serif;background:#fff1f2;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .card{background:#fff;padding:40px;border-radius:12px;border:2px solid #e11d48;text-align:center;width:400px;box-shadow:0 10px 25px rgba(225,29,72,.2)}
  h2{color:#e11d48;margin-top:0}
  button{width:100%;padding:14px;background:#e11d48;color:#fff;border:none;border-radius:6px;font-weight:bold;font-size:16px;margin-top:20px;cursor:pointer}
  input{width:100%;padding:12px;margin:8px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
</style></head><body>
<div class="card">
  <h2>⚠️ URGENT: DISCONNECTION NOTICE</h2>
  <p style="color:#4c0519;font-weight:bold;font-size:15px">Your electricity connection will be disconnected tonight at 9:30 PM.</p>
  <p style="color:#666;font-size:13px;margin-bottom:20px">Update KYC and pay ₹11 processing fee immediately.</p>
  <form><input placeholder="Consumer Number"><input placeholder="Mobile Number"><input placeholder="OTP"><button type="button">Pay ₹11 & Update KYC</button></form>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO E — Malicious APK Download (Plain HTML, links to /download-file)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/download') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>SBI YONO Rewards — Download</title>
<style>
  body{font-family:Arial,sans-serif;background:#e0f2fe;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .card{background:#fff;padding:40px;border-radius:12px;text-align:center;width:380px;box-shadow:0 10px 30px rgba(0,0,0,.1)}
  .btn{display:inline-block;width:100%;padding:16px;background:#0284c7;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;font-size:16px;margin-top:20px;box-sizing:border-box;text-align:center}
</style></head><body>
<div class="card">
  <h2 style="color:#0369a1;margin-top:0">SBI YONO Rewards</h2>
  <p style="color:#64748b;font-size:14px">Download your official rewards app update below.</p>
  <a class="btn" href="/downloads/sbi_yono_rewards.apk" id="dl-btn">Download APK</a>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO F — Pop-Up & Pop-Under Defusal Test Page
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/popup-test') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>Streaming HD Movie Hub — Pop-up Test</title>
<style>
  body{font-family:Arial,sans-serif;background:#0b0f19;color:#e2e8f0;padding:40px;display:flex;flex-direction:column;align-items:center}
  .box{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:32px;max-width:560px;width:100%;box-shadow:0 10px 30px rgba(0,0,0,.5)}
  h2{color:#38bdf8;margin-top:0}
  .btn-action{display:block;width:100%;padding:14px;margin:12px 0;border-radius:8px;border:none;font-size:15px;font-weight:bold;cursor:pointer;transition:.2s}
  .btn-red{background:#dc2626;color:#fff}
  .btn-amber{background:#d97706;color:#fff}
  .btn-blue{background:#2563eb;color:#fff}
  .status{margin-top:16px;padding:12px;background:#0f172a;border-radius:6px;font-family:monospace;font-size:13px;color:#a5f3fc}
</style></head><body>
<div class="box">
  <h2>🎬 Pop-up &amp; Pop-under Defusal Test</h2>
  <p style="color:#94a3b8;font-size:14px;line-height:1.5">
    Simulates real ad-network tricks used by streaming/piracy sites. With the Verity extension active, all unsolicited pop-up windows are instantly defused, showing an unobtrusive toast on this tab while keeping your window intact.
  </p>
  <button class="btn-action btn-red" id="btn-rotator">1. Trigger Ad-Rotator Pop-up (window.open)</button>
  <button class="btn-action btn-amber" id="btn-popup-win">2. Spawn Dimensioned Popup Window (about:blank trap)</button>
  <button class="btn-action btn-blue" id="btn-synthetic">3. Programmatic &lt;a target="_blank"&gt; Click</button>
  <div class="status" id="log-box">Status: Ready. Click any button to test Verity anti-popup protection.</div>
</div>
<script>
  const log = document.getElementById('log-box');
  document.getElementById('btn-rotator').onclick = () => {
    log.textContent = 'Calling window.open with ad-rotator URL...';
    const w = window.open('https://aar5n.wigglepoploaderfast.monster/?540267a373b920a51ea99c645c7f', '_blank');
    log.textContent = w?.closed ? '✅ Successfully DEFUSED by Verity! (Pop-up window was blocked)' : 'Invoked window.open';
  };
  document.getElementById('btn-popup-win').onclick = () => {
    log.textContent = 'Calling window.open with popup dimensions...';
    const w = window.open('about:blank', '_blank', 'width=450,height=550,popup=1');
    log.textContent = w?.closed ? '✅ Successfully DEFUSED by Verity! (Window trap defused)' : 'Invoked popup window';
  };
  document.getElementById('btn-synthetic').onclick = () => {
    log.textContent = 'Triggering synthetic click on ad link...';
    const a = document.createElement('a');
    a.href = 'https://adsterra.com/click?campaign=777';
    a.target = '_blank';
    document.body.appendChild(a);
    a.click();
    a.remove();
    log.textContent = '✅ Synthetic click processed by Verity shield.';
  };
</script>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO G — Browser-in-the-Browser (BitB) Fake OAuth Window
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/bitb') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>Claim Free Gaming Skins — OAuth Login</title>
<style>
  body{font-family:Arial,sans-serif;background:#0f172a;color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
  .fake-window{width:460px;background:#fff;color:#202124;border-radius:8px;box-shadow:0 15px 40px rgba(0,0,0,.6);overflow:hidden;border:1px solid #ccc}
  .fake-titlebar{background:#e8eaed;padding:8px 12px;display:flex;align-items:center;font-size:12px;color:#5f6368;border-bottom:1px solid #dadce0}
  .fake-url-bar{background:#fff;border:1px solid #dadce0;border-radius:16px;padding:4px 12px;font-size:12px;color:#1a73e8;flex:1;margin-left:8px;display:flex;align-items:center;gap:6px}
  .fake-content{padding:30px}
  input{width:100%;padding:12px;margin:8px 0;border:1px solid #dadce0;border-radius:4px;box-sizing:border-box}
  button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-weight:bold;cursor:pointer;margin-top:10px}
</style></head><body>
<div class="fake-window">
  <div class="fake-titlebar">
    <span>● ● ●</span>
    <div class="fake-url-bar">
      <span>🔒</span>
      <span>https://accounts.google.com/o/oauth2/v2/auth</span>
    </div>
  </div>
  <div class="fake-content">
    <h3 style="margin-top:0">Sign in with Google</h3>
    <p style="font-size:13px;color:#5f6368">Sign in to continue to Claim Free Skins Hub.</p>
    <form>
      <input type="text" placeholder="Email or phone">
      <input type="password" placeholder="Enter your password">
      <button type="button">Next</button>
    </form>
  </div>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO I — Malvertising Rotator Fast Redirect Trap
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url.startsWith('/demo/rotator-bridge')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>Rotator Bridge</title>
<script>
  window.location.href = '/demo/rotator-destination/iI0156mcDUnDMLQ/151718?param_4=1721489&param_5=5033194268461371774';
</script>
</head><body>
<p>Redirecting to landing page...</p>
</body></html>`);
  }

  if (req.url.startsWith('/demo/rotator-destination')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>Malvertising Landing Page</title>
<style>body{font-family:sans-serif;background:#111;color:#fff;text-align:center;padding:50px}</style>
</head><body>
<h1>Malvertising Destination Lander</h1>
<p>This destination was reached via a multi-hop ad rotator parameter sequence.</p>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HUB DASHBOARD
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/' || req.url === '/favicon.ico') {
    if (req.url === '/favicon.ico') { res.writeHead(204); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>Verity Demo Server</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;700&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Outfit',sans-serif;background:#020617;color:#f8fafc;min-height:100vh;padding:60px 40px;display:flex;flex-direction:column;align-items:center}
  h1{font-size:2.5rem;font-weight:700;margin-bottom:10px;text-align:center}
  h1 span{background:linear-gradient(135deg,#38bdf8,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
  p.sub{color:#94a3b8;margin-bottom:40px;text-align:center;font-size:1.1rem;max-width:650px;line-height:1.6}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:24px;width:100%;max-width:1150px}
  .card{background:rgba(30,41,59,.5);border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:26px;display:flex;flex-direction:column;gap:12px;transition:.3s}
  .card:hover{transform:translateY(-4px);background:rgba(30,41,59,.8);border-color:rgba(255,255,255,.2);box-shadow:0 10px 30px rgba(0,0,0,.3)}
  .card-title{font-size:1.25rem;font-weight:700}
  .card-desc{font-size:.92rem;color:#cbd5e1;line-height:1.5;font-weight:300;flex-grow:1}
  .expected{font-size:.8rem;color:#94a3b8;padding:6px 10px;background:rgba(255,255,255,.05);border-radius:6px;margin-top:4px}
  .expected b{color:#ef4444}
  .expected b.green{color:#22c55e}
  .btn{background:linear-gradient(135deg,#3b82f6,#2563eb);color:#fff;padding:12px;text-align:center;text-decoration:none;border-radius:10px;font-weight:bold;font-size:.95rem;transition:.2s;border:1px solid rgba(255,255,255,.1)}
  .btn:hover{background:linear-gradient(135deg,#60a5fa,#3b82f6);transform:scale(1.02)}
</style></head><body>
<h1>🛡️ Verity <span>Demo &amp; Testing Environment</span></h1>
<p class="sub">These demo pages serve plain HTML test fixtures without any client-side simulated overlays or mock scripts. The real Verity browser extension analyzes each page and download stream to produce security verdicts.</p>
<div class="grid">
  <div class="card">
    <div class="card-title">🏦 Fake Bank Login (Demo A)</div>
    <div class="card-desc">Realistic HDFC NetBanking login harvesting Customer ID, IPIN, and OTP on unverified origin.</div>
    <div class="expected">Expected: <b>🔴 BLOCK</b> — Brand Phishing &amp; Credential Harvesting overlay</div>
    <a class="btn" href="/demo/bank" target="_blank">Launch Banking Demo</a>
  </div>
  <div class="card">
    <div class="card-title">💳 Fake Payment Gateway (Demo B)</div>
    <div class="card-desc">PayPal checkout stealing Card Number, CVV, and OTP on an unverified domain.</div>
    <div class="expected">Expected: <b>🔴 BLOCK</b> — Payment Phishing overlay</div>
    <a class="btn" href="/demo/payment" target="_blank">Launch Payment Demo</a>
  </div>
  <div class="card">
    <div class="card-title">📲 UPI Cashback Scam (Demo C)</div>
    <div class="card-desc">Paytm reward trap hiding a malicious UPI debit link (upi://pay).</div>
    <div class="expected">Expected: <b>🔴 BLOCK</b> — Digital Scam Trap detected</div>
    <a class="btn" href="/demo/upi" target="_blank">Launch UPI Scam Demo</a>
  </div>
  <div class="card">
    <div class="card-title">⚡ Digital Arrest / KYC Notice (Demo D)</div>
    <div class="card-desc">Urgent utility disconnection notice demanding immediate KYC update &amp; fee.</div>
    <div class="expected">Expected: <b>🔴 BLOCK</b> — Digital Fraud &amp; Urgency Lure blocked</div>
    <a class="btn" href="/demo/utility" target="_blank">Launch KYC Scam Demo</a>
  </div>
  <div class="card">
    <div class="card-title">📦 Malicious APK Download (Demo E)</div>
    <div class="card-desc">Serves "sbi_yono_rewards.apk". Verity download monitor analyzes and cancels it.</div>
    <div class="expected">Expected: <b>🔴 CANCEL</b> — Download paused/cancelled + modal alert</div>
    <a class="btn" href="/demo/download" target="_blank">Launch Download Demo</a>
  </div>
  <div class="card">
    <div class="card-title">🛡️ Pop-up &amp; Pop-under Defusal (Demo F)</div>
    <div class="card-desc">Tests window.open ad rotators and popup dimension traps. Defused with toast notification.</div>
    <div class="expected">Expected: <b class="green">🟢 DEFUSED</b> — Pop-up blocked &amp; toast shown on opener</div>
    <a class="btn" href="/demo/popup-test" target="_blank">Launch Pop-up Demo</a>
  </div>
  <div class="card">
    <div class="card-title">🪟 BitB Fake OAuth Popup (Demo G)</div>
    <div class="card-desc">Browser-in-the-Browser fake Google OAuth window rendered in webpage DOM.</div>
    <div class="expected">Expected: <b>🔴 BLOCK</b> — BitB Fake OAuth Window detected</div>
    <a class="btn" href="/demo/bitb" target="_blank">Launch BitB Demo</a>
  </div>
  <div class="card">
    <div class="card-title">🔍 Search Badges (Demo H)</div>
    <div class="card-desc">Simulated Google Search page demonstrating green safe, yellow caution, and red danger badges.</div>
    <div class="expected">Expected: <b>🟢 🟡 🔴 BADGES</b> — In-page search result reputation badges</div>
    <a class="btn" href="/demo/google-search" target="_blank">Launch Search Badge Demo</a>
  </div>
  <div class="card">
    <div class="card-title">🔄 Malvertising Fast Redirect (Demo I)</div>
    <div class="card-desc">Simulates real-world rotator bridges (werefilledwit.org) that instantly client-redirect via inline script. Verity synchronously halts the parser and displays the block overlay.</div>
    <div class="expected">Expected: <b>🔴 BLOCK</b> — Synchronously halted &amp; Block Overlay shown</div>
    <a class="btn" href="/demo/rotator-bridge/RVV1SzVqahY4CBACBSZgAhseHgRwPyN5cxYARwFmHxNEGm8pAFMqVzFoQW1HIDFIehM2OEh6A2M+SG1DeGRbeAFrZk1lAmMmATgIdXMFOVt4ZVMuWCdoRW1BLDFIegJ3ZEFzDGMnDTIIdGBGfWp9Y0FtXCs2SHMTMGhEcwF9YEFyBHFtRHMCcWFEbVQiMBZ2BHJsRHMFcGFMeRMjJkh6EzcwE3ZdMSEFOBB2FFB5c2BnMy9aMjsZJFQhexgkQywwBjtUIjBbM0w" target="_blank">Launch Rotator Demo</a>
  </div>
</div>
</body></html>`);
  }

  res.writeHead(404);
  res.end('Not found');
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n❌ Error: Port ${PORT} is already in use by another instance.`);
    console.error(`👉 To free port ${PORT}, run in PowerShell:`);
    console.error(`   Stop-Process -Id (Get-NetTCPConnection -LocalPort ${PORT}).OwningProcess -Force\n`);
    process.exit(1);
  } else {
    throw err;
  }
});

server.listen(PORT, () => {
  console.log(`\n=======================================================`);
  console.log(`🚀 Verity Demo Server running at http://localhost:${PORT}`);
  console.log(`=======================================================\n`);
});
