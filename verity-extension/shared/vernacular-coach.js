/**
 * shared/vernacular-coach.js — Vernacular Voice AI & Plain-Language Cyber Literacy Coach
 *
 * Provides empathetic, plain-language citizen advisories in 4 Indian languages:
 * - English (en-IN)
 * - Hindi (hi-IN)
 * - Tamil (ta-IN)
 * - Telugu (te-IN)
 *
 * Integrates Web Speech API (window.speechSynthesis) for accessibility and rural digital literacy.
 */

export const HELPLINE_NUMBER = '1930';
export const NATIONAL_PORTAL = 'cybercrime.gov.in';
export const SUPPORTED_LANGS = ['en-IN', 'hi-IN', 'ta-IN', 'te-IN'];

  const ADVISORIES = {
    // ── 1. Illegal Web PIN Collection ──────────────────────────────────────────
    SIG_ILLEGAL_WEB_PIN_COLLECTION: {
      'en-IN': {
        title: 'Illegal UPI / ATM PIN Demand Detected',
        explanation: 'UPI PIN or ATM PIN is ONLY used when YOU are sending money, never for receiving cashback, refunds, or KYC verification.',
        goldenRule: 'Golden Rule: Never enter your UPI PIN to receive money or lottery prizes.',
        helpline: HELPLINE_NUMBER
      },
      'hi-IN': {
        title: 'अवैध UPI / ATM पिन की मांग पकड़ी गई',
        explanation: 'UPI पिन केवल पैसे भेजने के लिए होता है। पैसे प्राप्त करने, कैशबैक या KYC के लिए पिन कभी नहीं मांगा जाता।',
        goldenRule: 'गोल्डन नियम: पैसे प्राप्त करने के लिए कभी भी अपना UPI पिन दर्ज न करें।',
        helpline: HELPLINE_NUMBER
      },
      'ta-IN': {
        title: 'சட்டவிரோத UPI / ATM பின் கோரிக்கை கண்டறியப்பட்டது',
        explanation: 'UPI பின் என்பது பணம் அனுப்புவதற்கு மட்டுமே. பணம் பெறவோ, கேஷ்பேக் அல்லது KYC சரிபார்ப்பிற்கோ பின் தேவையில்லை.',
        goldenRule: 'தங்க விதி: பணம் பெற ஒருபோதும் UPI பின்னை உள்ளிடாதீர்கள்.',
        helpline: HELPLINE_NUMBER
      },
      'te-IN': {
        title: 'అనధికారిక UPI / ATM పిన్ డిమాండ్ గుర్తించబడింది',
        explanation: 'UPI పిన్ అనేది మీరు డబ్బు పంపడానికి మాత్రమే. డబ్బు పొందడానికి, క్యాష్‌బ్యాక్ లేదా KYC కోసం పిన్ అవసరం లేదు.',
        goldenRule: 'గోల్డెన్ రూల్: డబ్బు అందుకోవడానికి ఎప్పుడూ UPI పిన్ నమోదు చేయవద్దు.',
        helpline: HELPLINE_NUMBER
      }
    },

    // ── 2. Digital Arrest Extortion Scam ──────────────────────────────────────
    SIG_DIGITAL_ARREST_EXTORTION: {
      'en-IN': {
        title: 'Digital Arrest Extortion Scam Detected',
        explanation: 'Police, CBI, ED, Customs, RBI, or Judges NEVER conduct "Digital Arrests" over video calls or WhatsApp. Real law enforcement never demands money online to drop charges.',
        goldenRule: 'Golden Rule: Disconnect immediately. Dial 1930 or report on cybercrime.gov.in.',
        helpline: HELPLINE_NUMBER
      },
      'hi-IN': {
        title: 'डिजिटल अरेस्ट रंगदारी घोटाला पकड़ा गया',
        explanation: 'पुलिस, CBI, कस्टम्स या जज कभी भी वीडियो कॉल या व्हाट्सएप पर "डिजिटल अरेस्ट" नहीं करते। असली कानून प्रवर्तन एजेंसियां ऑनलाइन पैसे नहीं मांगतीं।',
        goldenRule: 'गोल्डन नियम: तुरंत कॉल काटें। तुरंत 1930 पर कॉल करें या cybercrime.gov.in पर रिपोर्ट करें।',
        helpline: HELPLINE_NUMBER
      },
      'ta-IN': {
        title: 'டிஜிட்டல் கைது மிரட்டல் மோசடி கண்டறியப்பட்டது',
        explanation: 'காவல்துறை, CBI, சுங்கம் அல்லது நீதிபதிகள் ஒருபோதும் வாட்ஸ்அப் அல்லது வீடியோ காலில் "டிஜிட்டல் கைது" செய்ய மாட்டார்கள். ஆன்லைனில் பணம் கோர மாட்டார்கள்.',
        goldenRule: 'தங்க விதி: உடனடியாக அழைப்பைத் துண்டிக்கவும். 1930-ஐ அழைக்கவும் அல்லது cybercrime.gov.in-ல் புகாரளிக்கவும்.',
        helpline: HELPLINE_NUMBER
      },
      'te-IN': {
        title: 'డిజిటల్ అరెస్ట్ దోపిడీ మోసం గుర్తించబడింది',
        explanation: 'పోలీసులు, CBI, కస్టమ్స్ లేదా న్యాయమూర్తులు వీడియో కాల్స్ లేదా వాట్సాప్‌లో "డిజిటల్ అరెస్ట్" చేయరు. ఆన్‌లైన్‌లో డబ్బు డిమాండ్ చేయరు.',
        goldenRule: 'గోల్డెన్ రూల్: వెంటనే కాల్ కట్ చేయండి. 1930 కి కాల్ చేయండి లేదా cybercrime.gov.in లో ఫిర్యాదు చేయండి.',
        helpline: HELPLINE_NUMBER
      }
    },

    // ── 3. Phishing Kit Webhook Exfil ─────────────────────────────────────────
    SIG_PHISHING_KIT_WEBHOOK_EXFIL: {
      'en-IN': {
        title: 'Data Stealing Spyware / Webhook Trap',
        explanation: 'This deceptive site is actively stealing your passwords and OTPs, sending them directly to a cyber criminal\'s private Telegram or Discord bot.',
        goldenRule: 'Golden Rule: Close this tab immediately. Change passwords if already typed.',
        helpline: HELPLINE_NUMBER
      },
      'hi-IN': {
        title: 'डेटा चोरी और वेबहुक जाल पकड़ा गया',
        explanation: 'यह फर्जी वेबसाइट आपके पासवर्ड और OTP चुराकर सीधे स्कैमर के टेलीग्राम या डिस्कोर्ड बॉट पर भेज रही है।',
        goldenRule: 'गोल्डन नियम: तुरंत इस टैब को बंद करें और अपने पासवर्ड बदलें।',
        helpline: HELPLINE_NUMBER
      },
      'ta-IN': {
        title: 'ரகசிய தரவு திருட்டு பொறி கண்டறியப்பட்டது',
        explanation: 'இந்த போலி தளம் உங்கள் கடவுச்சொல் மற்றும் OTP-ஐ திருடி, டெலிகிராம் அல்லது டிஸ்கார்ட் பாட்டிற்கு ரகசியமாக அனுப்புகிறது.',
        goldenRule: 'தங்க விதி: உடனடியாக இந்த தளத்தை மூடவும். கடவுச்சொல்லை மாற்றவும்.',
        helpline: HELPLINE_NUMBER
      },
      'te-IN': {
        title: 'డేటా దొంగతనం / వెబ్‌హుక్ ట్రాప్ గుర్తించబడింది',
        explanation: 'ఈ నకిలీ సైట్ మీ పాస్‌వర్డ్‌లు మరియు OTPలను దొంగిలించి, నేరస్థుడి టెలిగ్రామ్ లేదా డిస్కార్డ్ బాట్‌కు పంపుతోంది.',
        goldenRule: 'గోల్డెన్ రూల్: వెంటనే ఈ ట్యాబ్‌ను మూసివేయండి మరియు పాస్‌వర్డ్‌లను మార్చండి.',
        helpline: HELPLINE_NUMBER
      }
    },

    // ── 4. ClickFix Clipboard Attack ──────────────────────────────────────────
    SIG_CLICKFIX_CLIPBOARD_ATTACK: {
      'en-IN': {
        title: 'ClickFix Clipboard Malicious Command Injection',
        explanation: 'This page tried to trick you into copying hidden malicious commands into your clipboard to paste into Windows Run (Win+R) or PowerShell.',
        goldenRule: 'Golden Rule: Never paste (Ctrl+V) text from unknown sites into your computer\'s terminal or Run box.',
        helpline: HELPLINE_NUMBER
      },
      'hi-IN': {
        title: 'क्लिकफिक्स क्लिपबोर्ड कमांड इंजेक्शन',
        explanation: 'इस पेज ने आपके क्लिपबोर्ड पर खतरनाक कोड कॉपी करने की कोशिश की ताकि आप इसे विंडोज़ रन (Win+R) या पावरशेल में पेस्ट कर दें।',
        goldenRule: 'गोल्डन नियम: अज्ञात वेबसाइटों से कॉपी किए गए टेक्स्ट को कभी भी रन बॉक्स या टर्मिनल में पेस्ट न करें।',
        helpline: HELPLINE_NUMBER
      },
      'ta-IN': {
        title: 'கிளிக்பிக்ஸ் கிளிப்போர்டு மால்வேர் தாக்குதல்',
        explanation: 'இந்த தளம் உங்கள் கிளிப்போர்டில் ஆபத்தான கட்டளைகளை நகலெடுத்து, அதை Windows Run (Win+R)-ல் ஒட்ட வைக்க முயன்றது.',
        goldenRule: 'தங்க விதி: தெரியாத தளங்களிலிருந்து வரும் உரையை கணினி டெர்மினல் அல்லது ரன் பாக்ஸில் ஒருபோதும் பேஸ்ட் செய்யாதீர்கள்.',
        helpline: HELPLINE_NUMBER
      },
      'te-IN': {
        title: 'క్లిక్‌ఫిక్స్ క్లిప్‌బోర్డ్ మాల్వేర్ ఇంజెక్షన్',
        explanation: 'ఈ పేజీ మీ కంప్యూటర్ టెర్మినల్ లేదా విండోస్ రన్ (Win+R) లో హానికరమైన కోడ్‌ను పేస్ట్ చేయించడానికి మోసగించడానికి ప్రయత్నించింది.',
        goldenRule: 'గోల్డెన్ రూల్: తెలియని సైట్‌ల నుండి కాపీ చేసిన కోడ్‌ను ఎప్పుడూ రన్ బాక్స్‌లో పేస్ట్ చేయవద్దు.',
        helpline: HELPLINE_NUMBER
      }
    },

    // ── 5. UPI QR Code Collect Trap ───────────────────────────────────────────
    SIG_UPI_QR_COLLECT_TRAP: {
      'en-IN': {
        title: 'UPI QR Code Collect / Deduction Trap',
        explanation: 'Scanning a QR code or clicking this UPI collect request will DEDUCT money from your account, not credit it. You never scan a QR code to receive cashback or sale payments.',
        goldenRule: 'Golden Rule: Scanning a QR code only pays out money. It NEVER receives money.',
        helpline: HELPLINE_NUMBER
      },
      'hi-IN': {
        title: 'UPI QR कोड कटौती जाल पकड़ा गया',
        explanation: 'QR कोड स्कैन करने से आपके खाते से पैसे कटेंगे, जमा नहीं होंगे। कैशबैक या भुगतान प्राप्त करने के लिए कभी भी QR कोड स्कैन नहीं किया जाता।',
        goldenRule: 'गोल्डन नियम: QR कोड केवल पैसे भेजने के लिए स्कैन होता है, पैसे पाने के लिए कभी नहीं।',
        helpline: HELPLINE_NUMBER
      },
      'ta-IN': {
        title: 'UPI QR குறியீடு பணப்பறிப்பு பொறி',
        explanation: 'QR குறியீட்டை ஸ்கேன் செய்வது உங்கள் கணக்கிலிருந்து பணத்தை கழிக்கும், பணம் வராது. கேஷ்பேக் பெற ஒருபோதும் QR ஸ்கேன் செய்யக்கூடாது.',
        goldenRule: 'தங்க விதி: QR குறியீட்டை ஸ்கேன் செய்தால் பணம் போகும், வராது.',
        helpline: HELPLINE_NUMBER
      },
      'te-IN': {
        title: 'UPI QR కోడ్ డబ్బు కట్ చేసే ట్రాప్',
        explanation: 'QR కోడ్‌ని స్కాన్ చేయడం వల్ల మీ ఖాతా నుండి డబ్బు కట్ అవుతుంది కానీ జమ కాదు. క్యాష్‌బ్యాక్ లేదా పేమెంట్ కోసం QR కోడ్‌ను ఎప్పుడూ స్కాన్ చేయకూడదు.',
        goldenRule: 'గోల్డెన్ రూల్: QR కోడ్‌ను స్కాన్ చేస్తే డబ్బులు కట్ అవుతాయి తప్ప రావు.',
        helpline: HELPLINE_NUMBER
      }
    },

    // ── 6. Malicious APK Dropper ──────────────────────────────────────────────
    SIG_MALICIOUS_APK_DROPPER: {
      'en-IN': {
        title: 'Malicious Fake Government / Bank APK Dropper',
        explanation: 'This website is trying to install an unverified Android .apk application. Legitimate banks and government departments only distribute apps via Google Play Store.',
        goldenRule: 'Golden Rule: Never download or install APK files from WhatsApp, SMS, or unverified websites.',
        helpline: HELPLINE_NUMBER
      },
      'hi-IN': {
        title: 'फर्जी सरकारी / बैंक APK मैलवेयर पकड़ा गया',
        explanation: 'यह वेबसाइट एक अवैध एंड्रॉइड .apk ऐप इंस्टॉल करने की कोशिश कर रही है। बैंक और सरकारी सेवाएं केवल गूगल प्ले स्टोर से ऐप देती हैं।',
        goldenRule: 'गोल्डन नियम: व्हाट्सएप, SMS या अज्ञात वेबसाइटों से कभी भी APK फाइल डाउनलोड न करें।',
        helpline: HELPLINE_NUMBER
      },
      'ta-IN': {
        title: 'ஆபத்தான போலி அரசு / வங்கி APK கண்டறியப்பட்டது',
        explanation: 'இந்த தளம் சரிபார்க்கப்படாத Android .apk செயலியை நிறுவ முயல்கிறது. வங்கிகள் மற்றும் அரசு பயன்பாடுகள் Google Play Store மூலம் மட்டுமே கிடைக்கும்.',
        goldenRule: 'தங்க விதி: வாட்ஸ்அப் அல்லது தெரியாத தளங்களிலிருந்து APK கோப்புகளை ஒருபோதும் நிறுவ வேண்டாம்.',
        helpline: HELPLINE_NUMBER
      },
      'te-IN': {
        title: 'ప్రమాదకరమైన నకిలీ ప్రభుత్వ / బ్యాంక్ APK ట్రాప్',
        explanation: 'ఈ వెబ్‌సైట్ అనధికారిక Android .apk యాప్‌ను ఇన్‌స్టాల్ చేయడానికి ప్రయత్నిస్తోంది. బ్యాంకులు మరియు ప్రభుత్వాలు Google Play Store ద్వారా మాత్రమే యాప్‌లను అందిస్తాయి.',
        goldenRule: 'గోల్డెన్ రూల్: వాట్సాప్ లేదా తెలియని సైట్‌ల నుండి వచ్చే APK ఫైల్‌లను ఎప్పుడూ ఇన్‌స్టాల్ చేయవద్దు.',
        helpline: HELPLINE_NUMBER
      }
    },

    // ── 7. Rogue Ad-Rotator / Malvertising Redirect ───────────────────────────
    SIG_MALVERTISING_POPUP_NETWORK: {
      'en-IN': {
        title: 'Rogue Ad-Rotator / Malvertising Redirect Blocked',
        explanation: 'A button or hidden script tried to silently bounce your browser through an ad-rotator or rogue redirect chain to an unverified website.',
        goldenRule: 'Golden Rule: Close unexpected redirected tabs immediately. Never click "Allow" on surprise popups.',
        helpline: HELPLINE_NUMBER
      },
      'hi-IN': {
        title: 'अवांछित ऐड-रोटेटिंग और रीडायरेक्ट जाल रोका गया',
        explanation: 'वेबसाइट के किसी बटन या स्क्रिप्ट ने आपके ब्राउज़र को किसी अज्ञात विज्ञापन या रीडायरेक्ट नेटवर्क पर भेजने की कोशिश की।',
        goldenRule: 'गोल्डन नियम: अनचाहे खुले टैब को तुरंत बंद करें। अनजान पॉपअप पर कभी "Allow" न दबाएं।',
        helpline: HELPLINE_NUMBER
      },
      'ta-IN': {
        title: 'தேவையற்ற திசைதிருப்பல் / விளம்பர வலைப்பின்னல் தடுக்கப்பட்டது',
        explanation: 'முந்தைய பக்கத்திலுள்ள பொத்தான் அல்லது ஸ்கிரிப்ட் உங்கள் உலாவியை சரிபார்க்கப்படாத விளம்பர தளத்திற்கு திருப்பிவிட முயன்றது.',
        goldenRule: 'தங்க விதி: எதிர்பாராமல் திறக்கப்படும் பக்கங்களை உடனே மூடவும். "Allow" என்பதை அழுத்த வேண்டாம்.',
        helpline: HELPLINE_NUMBER
      },
      'te-IN': {
        title: 'అనవసరమైన రీడైరెక్ట్ / ప్రకటనల నెట్‌వర్క్ నిరోధించబడింది',
        explanation: 'మునుపటి వెబ్‌సైట్‌లోని బటన్ లేదా స్క్రిప్ట్ మీ బ్రౌజర్‌ను ధృవీకరించని ప్రకటనల సైట్‌కు బలవంతంగా పంపడానికి ప్రయత్నించింది.',
        goldenRule: 'గోల్డెన్ రూల్: అనుకోకుండా తెరుచుకునే ట్యాబ్‌లను వెంటనే మూసివేయండి. పాపప్‌లలో "Allow" నొక్కవద్దు.',
        helpline: HELPLINE_NUMBER
      }
    }
  };

  // Generic fallback advisory for other signals
  const DEFAULT_ADVISORY = {
    'en-IN': {
      title: 'High-Risk Cyber Threat Blocked',
      explanation: 'Verity has blocked this untrusted website to protect your financial accounts, personal identity, and computer from unauthorized access.',
      goldenRule: 'Golden Rule: Do not enter sensitive credentials on unverified websites. Call 1930 if money was lost.',
      helpline: HELPLINE_NUMBER
    },
    'hi-IN': {
      title: 'उच्च जोखिम वाला साइबर खतरा रोका गया',
      explanation: 'वेरिटी ने आपके बैंक खाते, निजी जानकारी और डिवाइस की सुरक्षा के लिए इस संदिग्ध वेबसाइट को ब्लॉक कर दिया है।',
      goldenRule: 'गोल्डन नियम: असत्यापित वेबसाइटों पर कभी पासवर्ड या OTP न डालें। नुकसान होने पर 1930 डायल करें।',
      helpline: HELPLINE_NUMBER
    },
    'ta-IN': {
      title: 'அதிக ஆபத்துள்ள இணைய அச்சுறுத்தல் தடுக்கப்பட்டது',
      explanation: 'உங்கள் வங்கி கணக்கு மற்றும் தனிப்பட்ட தரவுகளைப் பாதுகாக்க இந்த சந்தேகத்திற்கிடமான தளத்தை வெரிட்டி தடுத்துள்ளது.',
      goldenRule: 'தங்க விதி: சரிபார்க்கப்படாத தளங்களில் கடவுச்சொல் உள்ளிடாதீர்கள். பண இழப்பு ஏற்பட்டால் 1930-ஐ அழைக்கவும்.',
      helpline: HELPLINE_NUMBER
    },
    'te-IN': {
      title: 'అధిక ప్రమాదకరమైన సైబర్ ముప్పు నిరోధించబడింది',
      explanation: 'మీ బ్యాంక్ ఖాతా మరియు వ్యక్తిగత డేటాను రక్షించడానికి వెరిటీ ఈ అనుమానాస్పద సైట్‌ను బ్లాక్ చేసింది.',
      goldenRule: 'గోల్డెన్ రూల్: ధృవీకరించని సైట్‌లలో పాస్‌వర్డ్‌లను నమోదు చేయవద్దు. డబ్బు నష్టపోతే 1930 కి కాల్ చేయండి.',
      helpline: HELPLINE_NUMBER
    }
  };

  /**
   * Retrieves localized, plain-language advisory object for a given signal.
   *
   * @param {string} signalId - Threat signal identifier
   * @param {string} [lang='en-IN'] - Locale identifier (en-IN, hi-IN, ta-IN, te-IN)
   * @returns {{ title: string, explanation: string, goldenRule: string, helpline: string, lang: string }}
   */
  function getVernacularAdvisory(signalId, lang = 'en-IN') {
    const selectedLang = SUPPORTED_LANGS.includes(lang) ? lang : 'en-IN';
    const effectiveSignal = (
      signalId === 'SIG_CHAIN_HOP_REDIRECT' ||
      signalId === 'SIG_FAST_FLUX_REDIRECT_LOOP' ||
      signalId === 'SIG_ROGUE_POPUP_WINDOW_BLOCKED' ||
      signalId === 'SIG_AD_ROTATOR_TRAFFIC' ||
      signalId === 'SIG_UNVERIFIED_REDIRECT_TRAP'
    ) ? 'SIG_MALVERTISING_POPUP_NETWORK' : signalId;
    const signalData = ADVISORIES[effectiveSignal];

    if (signalData && signalData[selectedLang]) {
      return {
        ...signalData[selectedLang],
        lang: selectedLang,
        portal: NATIONAL_PORTAL
      };
    }

    if (DEFAULT_ADVISORY[selectedLang]) {
      return {
        ...DEFAULT_ADVISORY[selectedLang],
        lang: selectedLang,
        portal: NATIONAL_PORTAL
      };
    }

    return {
      ...DEFAULT_ADVISORY['en-IN'],
      lang: 'en-IN',
      portal: NATIONAL_PORTAL
    };
  }

  /**
   * Reads aloud the plain-language vernacular advisory using browser SpeechSynthesis.
   * Gracefully handles environments without speech synthesis (e.g. Node.js unit tests).
   *
   * @param {string} signalId - Threat signal identifier
   * @param {string} [lang='en-IN'] - Locale identifier
   * @returns {{ spoken: boolean, text: string, lang: string, reason?: string }}
   */
  function speakVernacularAdvisory(signalId, lang = 'en-IN') {
    const advisory = getVernacularAdvisory(signalId, lang);
    const textToSpeak = `${advisory.title}. ${advisory.explanation} ${advisory.goldenRule}`;

    if (typeof window !== 'undefined' && window.speechSynthesis && typeof window.SpeechSynthesisUtterance === 'function') {
      try {
        window.speechSynthesis.cancel(); // Stop any pending speech
        const utterance = new window.SpeechSynthesisUtterance(textToSpeak);
        utterance.lang = advisory.lang;
        utterance.rate = 0.95; // Slightly slower for clarity and comprehension
        utterance.pitch = 1.0;
        window.speechSynthesis.speak(utterance);
        return { spoken: true, text: textToSpeak, lang: advisory.lang };
      } catch (err) {
        return { spoken: false, text: textToSpeak, lang: advisory.lang, reason: err.message };
      }
    }

    // Node.js or browser without Web Speech API
    return {
      spoken: false,
      text: textToSpeak,
      lang: advisory.lang,
      reason: 'speech_synthesis_unavailable'
    };
  }

  export {
    getVernacularAdvisory,
    speakVernacularAdvisory,
    ADVISORIES,
    DEFAULT_ADVISORY
  };

  if (typeof globalThis !== 'undefined') {
    globalThis.HELPLINE_NUMBER = HELPLINE_NUMBER;
    globalThis.NATIONAL_PORTAL = NATIONAL_PORTAL;
    globalThis.SUPPORTED_LANGS = SUPPORTED_LANGS;
    globalThis.getVernacularAdvisory = getVernacularAdvisory;
    globalThis.speakVernacularAdvisory = speakVernacularAdvisory;
    globalThis.VerityVernacularCoach = {
      HELPLINE_NUMBER,
      NATIONAL_PORTAL,
      SUPPORTED_LANGS,
      getVernacularAdvisory,
      speakVernacularAdvisory
    };
  }

  export default {
    HELPLINE_NUMBER,
    NATIONAL_PORTAL,
    SUPPORTED_LANGS,
    getVernacularAdvisory,
    speakVernacularAdvisory
  };
