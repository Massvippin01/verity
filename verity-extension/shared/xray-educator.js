/**
 * shared/xray-educator.js — Interactive "Spot The Scam" X-Ray Literacy Engine
 *
 * Generates interactive, educational teaching cards for blocked pages:
 * 1. URL Anatomy Breakdown (demystifying subdomains vs. true registrable domains)
 * 2. Attacker Psychological Trigger (Fear/Authority, Greed/Reward, Artificial Urgency)
 * 3. Interactive Micro-Quiz with immediate feedback to build citizen cyber immunity
 */

'use strict';

  function parseUrlAnatomy(urlString) {
    let hostname = 'unknown-host';
    let protocol = 'http:';
    let path = '/';

    try {
      const urlToParse = (urlString && urlString.includes('://')) ? urlString : `http://${urlString || 'unknown-host'}`;
      const u = new URL(urlToParse);
      hostname = u.hostname.toLowerCase();
      protocol = u.protocol;
      path = u.pathname;
    } catch (_) {
      hostname = (urlString || '').toLowerCase().split('/')[0];
    }

    const parts = hostname.split('.').filter(Boolean);
    let registeredDomain = hostname;
    let subdomains = '';

    if (parts.length >= 2) {
      // Handles basic 2-level TLDs (.co.in, .com.au, etc.)
      const isSecondLevelTld = parts.length >= 3 && ['co', 'gov', 'ac', 'net', 'org', 'res'].includes(parts[parts.length - 2]);
      const domainParts = isSecondLevelTld ? parts.slice(-3) : parts.slice(-2);
      registeredDomain = domainParts.join('.');
      const subParts = isSecondLevelTld ? parts.slice(0, -3) : parts.slice(0, -2);
      subdomains = subParts.join('.');
    }

    return {
      hostname,
      registeredDomain,
      subdomains,
      protocol,
      path
    };
  }

  function detectPsychologicalTrigger(analysisResult = {}) {
    const signals = analysisResult.signals || [];
    const reasons = analysisResult.reasons || [];
    const corpus = (signals.map(s => s.id || s).join(' ') + ' ' + reasons.map(r => r.reason || r).join(' ')).toLowerCase();

    // 1. Fear & False Authority
    if (corpus.includes('digital_arrest') || corpus.includes('police') || corpus.includes('cbi') || corpus.includes('customs') || corpus.includes('kyc_cyber_fraud') || corpus.includes('warrant')) {
      return {
        type: 'FEAR_AND_AUTHORITY',
        title: 'Attacker Psychology: Fear & False Authority',
        badge: 'Intimidation Tactic',
        explanation: 'Scammers impersonate police officers, CBI agents, or judges ("Digital Arrest") to induce extreme panic so you comply before consulting family or legal counsel.',
        countermeasure: 'Real police and courts NEVER conduct trials over WhatsApp or Skype, nor do they ask for bank transfers to drop charges. Disconnect and call 1930 immediately.'
      };
    }

    // 2. Greed & Fake Rewards
    if (corpus.includes('qr_collect') || corpus.includes('cashback') || corpus.includes('bonus') || corpus.includes('lottery') || corpus.includes('reward') || corpus.includes('upi_debit_trap')) {
      return {
        type: 'GREED_AND_REWARD',
        title: 'Attacker Psychology: Fake Rewards & Cashback Lures',
        badge: 'Greed / Excitement Tactic',
        explanation: 'The scammer triggers excitement with fake cashback or lottery claims, tricking you into believing you are receiving money when you are actually authorizing a withdrawal.',
        countermeasure: 'You NEVER need to enter your UPI PIN or scan a QR code to receive money. Scanning a QR code only pays OUT money.'
      };
    }

    // 3. Artificial Urgency
    if (corpus.includes('timer') || corpus.includes('high_pressure') || corpus.includes('electricity') || corpus.includes('bill') || corpus.includes('disconnection')) {
      return {
        type: 'ARTIFICIAL_URGENCY',
        title: 'Attacker Psychology: Artificial Panic & Urgency',
        badge: 'Time-Pressure Tactic',
        explanation: 'Scammers manufacture artificial 24-hour deadlines or power disconnection threats to bypass your analytical thinking and rush your actions.',
        countermeasure: 'Slow down. Legitimate utilities and banks never cut services without multi-day official paper notices. Verify on official apps only.'
      };
    }

    // 4. Forced Redirect / Ad-Rotator Network (User-redirected ad network scenario)
    if (corpus.includes('redirect') || corpus.includes('rotator') || corpus.includes('popunder') || corpus.includes('adware') || corpus.includes('popup') || corpus.includes('malvertising') || corpus.includes('chain_hop')) {
      return {
        type: 'FORCED_REDIRECT_NETWORK',
        title: 'Attacker Tactic: Forced Ad-Rotator Redirect',
        badge: 'Forced Navigation Trap',
        explanation: 'A button or hidden script hijacked your click to silently bounce your browser through an ad-rotator or rogue redirect chain to an unverified website.',
        countermeasure: 'Do not click anywhere inside the redirected page, and do not accept notification or software download prompts. Close the tab immediately.'
      };
    }

    // Default: Deceptive Familiarity & Unverified Domain
    return {
      type: 'DECEPTIVE_FAMILIARITY',
      title: 'Attacker Psychology: Deceptive Brand & Domain Spoofing',
      badge: 'Impersonation / Spoofing Tactic',
      explanation: 'Scammers use unverified domains, deceptive subdomains, or copied visual themes to trick users into trusting an unauthorized website.',
      countermeasure: 'Look at the address bar, not the website design. Anyone can copy a design or buy an untrusted domain, but only the registered domain dictates the true owner.'
    };
  }

  function generateContextualQuiz(analysisResult = {}, anatomy = {}) {
    const signals = analysisResult.signals || [];
    const reasons = analysisResult.reasons || [];
    const corpus = (
      signals.map(s => s.id || s).join(' ') + ' ' +
      reasons.map(r => r.reason || r).join(' ')
    ).toLowerCase();

    // 1. Digital Arrest Quiz
    if (corpus.includes('digital_arrest') || corpus.includes('police') || corpus.includes('cbi')) {
      return {
        question: 'A WhatsApp video caller in police uniform claims your Aadhaar is tied to a narcotics parcel and demands ₹50,000 for "verification bail". What should you do?',
        options: [
          'Immediately transfer the funds to avoid arrest',
          'Disconnect immediately and dial 1930 or visit cybercrime.gov.in',
          'Send photos of your family members to prove your innocence',
          'Ask the caller for his police badge ID number and pay half'
        ],
        correctIndex: 1,
        explanation: 'Indian law enforcement agencies NEVER issue "Digital Arrests", conduct video call court hearings, or demand online fund transfers. Disconnect and call 1930 immediately.'
      };
    }

    // 2. UPI QR Code Trap Quiz
    if (corpus.includes('upi') || corpus.includes('qr') || corpus.includes('pin')) {
      return {
        question: 'An online buyer sends you a QR code saying: "Scan this and enter your UPI PIN to claim your ₹5,000 payment". What will actually happen?',
        options: [
          '₹5,000 will be credited to your bank account',
          '₹5,000 will be deducted from your bank account',
          'Nothing will happen until you receive an OTP',
          'You will receive a scratch card bonus'
        ],
        correctIndex: 1,
        explanation: 'Entering your UPI PIN authorizes money leaving your account. You NEVER need to enter your PIN to receive money or refunds.'
      };
    }

    // 3. Malicious APK Quiz
    if (corpus.includes('apk') || corpus.includes('download') || corpus.includes('.exe')) {
      return {
        question: 'You receive an SMS saying your electricity will be disconnected tonight unless you download "Electricity_Bill.apk". What is the safest action?',
        options: [
          'Download and install the APK file immediately',
          'Delete the message and check your bill on the official power utility app from Google Play Store',
          'Forward the message to neighbours to check if they received it',
          'Call the mobile number listed in the SMS'
        ],
        correctIndex: 1,
        explanation: 'Unverified APK files sent over SMS or WhatsApp are banking trojans that secretly steal your SMS OTPs. Official utility apps are only on Google Play Store.'
      };
    }

    // 4. Rogue Redirects / Ad Rotators / Malvertising Quiz (The user's exact case)
    if (corpus.includes('redirect') || corpus.includes('rotator') || corpus.includes('popunder') || corpus.includes('adware') || corpus.includes('malvertising') || corpus.includes('popup') || corpus.includes('chain_hop')) {
      return {
        question: `You clicked a button or link, and it unexpectedly redirected to "${anatomy.hostname || anatomy.registeredDomain || 'an unfamiliar site'}". What is the safest action?`,
        options: [
          'Close the redirected page immediately without clicking or downloading anything',
          'Click "Allow" or "Accept" if prompted for notification or browser permissions',
          'Follow the page instructions to install recommended software updates',
          'Enter your mobile number or email to proceed to your intended destination'
        ],
        correctIndex: 0,
        explanation: 'Ad-rotator networks and rogue redirects silently divert clicks to push scams, unwanted software, or fake alerts. Closing the unexpected tab immediately keeps your browser safe.'
      };
    }

    // 5. Brand Impersonation (ONLY when a specific brand was actually detected!)
    let detectedBrand = analysisResult.brand || analysisResult.detectedBrand || null;
    if (!detectedBrand) {
      const brandMatch = corpus.match(/impersonating ["']?([^"']+)["']?|claims to be ["']?([^"']+)["']?/i);
      if (brandMatch) detectedBrand = brandMatch[1] || brandMatch[2];
    }

    if (detectedBrand) {
      return {
        question: `This website claims to be "${detectedBrand}", but the browser address is "https://${anatomy.hostname}". Who owns this website?`,
        options: [
          `The official ${detectedBrand} company or organization`,
          `The owner of "${anatomy.registeredDomain}", which is an unauthorized third party`,
          'Your internet service provider',
          'The Government of India'
        ],
        correctIndex: 1,
        explanation: `Anyone can copy the logo or name of "${detectedBrand}", but the registered domain "${anatomy.registeredDomain}" proves this is an unauthorized clone.`
      };
    }

    // 6. Subdomain Deception Quiz (if subdomains exist, e.g. login.verify.trap.org)
    if (anatomy.subdomains && anatomy.subdomains !== 'www') {
      return {
        question: `In the web address "https://${anatomy.hostname}", which part determines who actually owns and operates this website?`,
        options: [
          `The prefix subdomains ("${anatomy.subdomains}") at the start`,
          `The registered root domain ("${anatomy.registeredDomain}") at the end`,
          'The "https://" secure connection padlock',
          'Whichever brand logo is displayed on the page'
        ],
        correctIndex: 1,
        explanation: `Scammers can prefix deceptive words as subdomains, but only the registered root domain ("${anatomy.registeredDomain}") dictates true ownership.`
      };
    }

    // 7. General Unverified Domain Quiz (e.g. werefilledwit.org with no subdomains and no brand)
    return {
      question: `You were directed to "https://${anatomy.registeredDomain || 'an-unknown-domain.org'}". How can you know if an unfamiliar website is genuine?`,
      options: [
        'Trust it if it displays a green lock icon or HTTPS in the address bar',
        'Verify the web address through official channels before entering any details',
        'Trust it if it promises fast downloads or instant rewards',
        'Assume it is safe because your browser opened it without an error'
      ],
      correctIndex: 1,
      explanation: `Anyone can register an inexpensive domain like "${anatomy.registeredDomain || 'this site'}" with free HTTPS encryption. Always verify addresses independently.`
    };
  }

  /**
   * Generates a 3-part interactive educational curriculum tailored to the specific threat.
   *
   * @param {object} analysisResult - Evaluation result from risk engine
   * @param {string} urlString - Suspect URL
   * @returns {{ cards: object[], totalCards: number, summaryText: string }}
   */
  function generateXRayTeachingCards(analysisResult = {}, urlString = '') {
    const anatomy = parseUrlAnatomy(urlString);
    const trigger = detectPsychologicalTrigger(analysisResult);
    const quiz = generateContextualQuiz(analysisResult, anatomy);

    const cards = [
      // ── Card 1: URL Anatomy ────────────────────────────────────────────────
      {
        cardType: 'URL_ANATOMY',
        title: 'URL Anatomy: Where are you really going?',
        badge: 'Technical X-Ray',
        registeredDomain: anatomy.registeredDomain,
        subdomains: anatomy.subdomains,
        hostname: anatomy.hostname,
        takeaway: anatomy.subdomains
          ? `The scammer added "${anatomy.subdomains}" to deceive you, but you are actually connecting to "${anatomy.registeredDomain}".`
          : `You are connecting directly to "${anatomy.registeredDomain}", which is an unverified domain.`
      },

      // ── Card 2: Psychological Tactic ───────────────────────────────────────
      {
        cardType: 'PSYCHOLOGICAL_TACTIC',
        title: trigger.title,
        badge: trigger.badge,
        explanation: trigger.explanation,
        countermeasure: trigger.countermeasure
      },

      // ── Card 3: Interactive Micro-Quiz ─────────────────────────────────────
      {
        cardType: 'MICRO_QUIZ',
        title: 'Spot The Scam: Citizen Immunity Check',
        badge: 'Interactive Micro-Quiz',
        question: quiz.question,
        options: quiz.options,
        correctIndex: quiz.correctIndex,
        explanation: quiz.explanation
      }
    ];

    const summaryText = `[Spot The Scam X-Ray] Domain: ${anatomy.registeredDomain} | Tactic: ${trigger.title} | Quiz: ${quiz.question}`;

    return {
      cards,
      totalCards: cards.length,
      summaryText
    };
  }

  export {
    parseUrlAnatomy,
    detectPsychologicalTrigger,
    generateContextualQuiz,
    generateXRayTeachingCards
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.parseUrlAnatomy = parseUrlAnatomy;
    globalThis.detectPsychologicalTrigger = detectPsychologicalTrigger;
    globalThis.generateContextualQuiz = generateContextualQuiz;
    globalThis.generateXRayTeachingCards = generateXRayTeachingCards;
    globalThis.VerityXRayEducator = {
      parseUrlAnatomy,
      detectPsychologicalTrigger,
      generateContextualQuiz,
      generateXRayTeachingCards
    };
  }

  export default {
    parseUrlAnatomy,
    detectPsychologicalTrigger,
    generateContextualQuiz,
    generateXRayTeachingCards
  };
