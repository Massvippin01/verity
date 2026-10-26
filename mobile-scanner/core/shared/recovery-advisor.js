/**
 * shared/recovery-advisor.js — Citizen Cyber Incident Recovery & Evidence Preservation
 *
 * Provides structured decision trees and actionable emergency guidance for citizens
 * who may have already interacted with a cyber scam or financial fraud attempt.
 *
 * Universal portability: Zero browser extension APIs and zero DOM dependencies.
 */

/**
 * Official verified Indian emergency helplines and portals.
 * Maintained as an explicit configuration registry.
 */
export const OFFICIAL_RECOVERY_REGISTRY = Object.freeze({
  helpline: {
    number: '1930',
    title: 'Citizen Financial Cyber Fraud Reporting System (CFCFRMS / I4C)',
    hours: '24x7 National Toll-Free',
    purpose: 'Report financial loss within the Golden Hour to freeze transiting funds.'
  },
  portal: {
    url: 'https://cybercrime.gov.in',
    title: 'National Cyber Crime Reporting Portal (MHA / I4C)',
    purpose: 'Official online FIR / police complaint registration across all Indian States and UTs.'
  },
  telecomChakshu: {
    url: 'https://sancharsaathi.gov.in/sanchar-saathi-services.html',
    title: 'DoT Sanchar Saathi / Chakshu Portal',
    purpose: 'Report fraudulent WhatsApp / SMS numbers, spoofed calls, and SIM misuse.'
  },
  aadhaarLock: {
    url: 'https://myaadhaar.uidai.gov.in',
    title: 'UIDAI Aadhaar Biometric Lock',
    purpose: 'Instantly lock Aadhaar biometric authentication to stop AePS fraud.'
  },
  rbiSachet: {
    url: 'https://sachet.rbi.org.in',
    title: 'RBI Sachet Portal',
    purpose: 'File complaints against unregistered lenders, illegal loan apps, and deposit schemes.'
  },
  sebiScores: {
    url: 'https://scores.sebi.gov.in',
    title: 'SEBI SCORES Portal',
    purpose: 'Report fraudulent investment advisors, fake stock trading apps, and Ponzi schemes.'
  },
  bankHelplines: [
    { bank: 'State Bank of India (SBI)', phone: '18001234', emergencySms: 'BLOCK <last 4 digits> to 567676' },
    { bank: 'HDFC Bank', phone: '18002026161', emergencySms: 'SMS BLOCK <last 4 digits> to 5676712' },
    { bank: 'ICICI Bank', phone: '18001080', emergencySms: 'SMS BLOCK <last 4 digits> to 9215676766' },
    { bank: 'Axis Bank', phone: '18604195555', emergencySms: 'SMS BLOCKCARD <last 4 digits> to 56161600' },
    { bank: 'Punjab National Bank (PNB)', phone: '18001802222', emergencySms: 'SMS HOT <card number> to 5607040' },
    { bank: 'Bank of Baroda', phone: '18005700', emergencySms: 'SMS BLOCK <last 4 digits> to 8422009988' }
  ]
});

/**
 * 10 Citizen Action States supported by the Recovery Decision Tree.
 */
export const INCIDENT_TYPES = Object.freeze([
  'CLICKED_SUSPICIOUS_LINK',
  'ENTERED_PASSWORD',
  'SHARED_OTP_OR_PIN',
  'ENTERED_PAYMENT_DETAILS',
  'APPROVED_PAYMENT_OR_TRANSFERRED',
  'INSTALLED_SUSPICIOUS_APP',
  'GRANTED_REMOTE_ACCESS_OR_ACCESSIBILITY',
  'SHARED_IDENTITY_DOCUMENTS',
  'EXTORTION_OR_DIGITAL_ARREST',
  'UNCERTAIN_WHAT_HAPPENED'
]);

/**
 * Localized recovery guidance steps across EN, TA, HI, TE.
 */
export const RECOVERY_GUIDES = {
  CLICKED_SUSPICIOUS_LINK: {
    title: {
      en: 'Clicked a Suspicious Link',
      ta: 'சந்தேகத்திற்கிடமான இணைப்பைக் கிளிக் செய்துவிட்டேன்',
      hi: 'संदिग्ध लिंक पर क्लिक कर दिया',
      te: 'అనుమానాస్పద లింక్‌పై క్లిక్ చేసాను'
    },
    urgency: 'medium',
    steps: {
      en: [
        'Close the browser tab immediately and do not download or open any prompted files.',
        'Clear your browser cache, cookies, and active session data.',
        'Do not enter any passwords, phone numbers, or OTPs on that page.',
        'Monitor your bank accounts and email for any unexpected login or transaction alerts.'
      ],
      ta: [
        'உடனடியாக பிரவுசர் டேப்பை மூடவும்; எந்த கோப்பையும் பதிவிறக்கவோ திறக்கவோ வேண்டாம்.',
        'உங்கள் பிரவுசரின் தற்காலிக நினைவகம் (Cache), குக்கீகள் (Cookies) மற்றும் அமர்வுத் தரவை அழிக்கவும்.',
        'அந்தப் பக்கத்தில் கடவுச்சொற்கள், தொலைபேசி எண்கள் அல்லது OTP-களை ஒருபோதும் உள்ளிட வேண்டாம்.',
        'எதிர்பாராத உள்நுழைவு அல்லது பணப்பரிவர்த்தனை எச்சரிக்கைகள் வருகிறதா என்று வங்கி கணக்கை கண்காணிக்கவும்.'
      ],
      hi: [
        'ब्राउज़र टैब को तुरंत बंद करें और किसी भी फ़ाइल को डाउनलोड या ओपन न करें।',
        'अपने ब्राउज़र की कैश, कुकीज़ और एक्टिव सेशन डेटा को तुरंत क्लियर करें।',
        'उस पेज पर कोई भी पासवर्ड, फोन नंबर या ओटीपी दर्ज न करें।',
        'अपने बैंक खातों और ईमेल पर किसी भी अप्रत्याशित लॉगिन या अलर्ट पर नजर रखें।'
      ],
      te: [
        'వెంటనే బ్రౌజర్ ట్యాబ్‌ను మూసివేయండి మరియు డౌన్‌లోడ్ అయిన ఫైళ్ళను తెరవకండి.',
        'మీ బ్రౌజర్ క్యాష్ (Cache) మరియు కుకీలను క్లియర్ చేయండి.',
        'ఆ పేజీలో ఎలాంటి పాస్‌వర్డ్‌లు లేదా OTPలను నమోదు చేయవద్దు.',
        'మీ బ్యాంక్ ఖాతా మెసేజ్‌లను గమనిస్తూ ఉండండి.'
      ]
    },
    officialChannels: ['telecomChakshu']
  },

  ENTERED_PASSWORD: {
    title: {
      en: 'Entered Password or Login Credentials',
      ta: 'கடவுச்சொல் அல்லது உள்நுழைவு விவரங்களை உள்ளிட்டுவிட்டேன்',
      hi: 'पासवर्ड या लॉगिन विवरण दर्ज कर दिया',
      te: 'పాస్‌వర్డ్ లేదా లాగిన్ వివరాలు నమోదు చేసాను'
    },
    urgency: 'high',
    steps: {
      en: [
        'Log in immediately from a trusted device and change the password for that account.',
        'Terminate all active sessions/devices under Account Security settings.',
        'If you reused that password on other accounts (email, banking), change those immediately.',
        'Enable Two-Factor Authentication (2FA) using an Authenticator app (prefer app over SMS).'
      ],
      ta: [
        'உடனடியாக வேறொரு பாதுகாப்பான சாதனத்திலிருந்து உள்நுழைந்து அந்த கணக்கின் கடவுச்சொல்லை மாற்றவும்.',
        'பாதுகாப்பு அமைப்புகளில் (Security settings) சென்று அனைத்து செயலில் உள்ள சாதனங்களிலிருந்தும் வெளியேறவும் (Logout).',
        'இதே கடவுச்சொல்லை பிற கணக்குகளுக்குப் பயன்படுத்தியிருந்தால், அவற்றையும் உடனே மாற்றவும்.',
        'அங்கீகார செயலி (Authenticator App) மூலமாக இரு காரணி அங்கீகாரத்தை (2FA) இயக்கவும்.'
      ],
      hi: [
        'तुरंत किसी सुरक्षित डिवाइस से लॉगिन करें और उस खाते का पासवर्ड बदलें।',
        'सिक्योरिटी सेटिंग्स में जाकर सभी एक्टिव सेशन और डिवाइस से लॉग आउट करें।',
        'यदि आपने यही पासवर्ड अन्य खातों (ईमेल, बैंक) पर भी रखा था, तो उन्हें भी तुरंत बदलें।',
        'ऑथेंटिकेटर ऐप का उपयोग करके टू-फैक्टर ऑथेंटिकेशन (2FA) तुरंत चालू करें।'
      ],
      te: [
        'వెంటనే నమ్మకమైన పరికరం నుండి లాగిన్ అయి పాస్‌వర్డ్‌ను మార్చండి.',
        'సెక్యూరిటీ సెట్టింగ్స్‌లో అన్ని యాక్టివ్ సెషన్‌ల నుండి లాగ్ అవుట్ చేయండి.',
        'ఇదే పాస్‌వర్డ్ ఇతర ఖాతాలలో ఉంటే వాటిని కూడా వెంటనే మార్చండి.',
        'టూ-ఫ్యాక్టర్ ప్రామాణీకరణను (2FA) ప్రారంభించండి.'
      ]
    },
    officialChannels: ['portal']
  },

  SHARED_OTP_OR_PIN: {
    title: {
      en: 'Shared OTP, ATM PIN, or UPI PIN',
      ta: 'OTP, ஏடிஎம் பின் அல்லது யுபிஐ பின்னைப் பகிர்ந்துவிட்டேன்',
      hi: 'ओटीपी, एटीएम पिन या यूपीआई पिन साझा कर दिया',
      te: 'OTP లేదా UPI పిన్ షేర్ చేసాను'
    },
    urgency: 'critical',
    steps: {
      en: [
        'Call your bank helpline immediately and request to temporarily block and freeze your netbanking and debit card.',
        'Open your UPI app (Google Pay, PhonePe, Paytm, BHIM) and change/reset your UPI PIN immediately.',
        'Do not share any follow-up OTPs with callers claiming to "reverse" or "cancel" the transaction.',
        'Call national helpline 1930 immediately if money has already been deducted.'
      ],
      ta: [
        'உடனடியாக உங்கள் வங்கி வாடிக்கையாளர் சேவைக்கு அழைத்து, நெட்பேங்கிங் மற்றும் கார்டை முடக்க (Block) கோரவும்.',
        'உங்கள் UPI செயலியைத் திறந்து (GPay, PhonePe, Paytm) உடனே UPI PIN-ஐ மாற்றவும்/ரீசெட் செய்யவும்.',
        'பணத்தை திரும்பப் பெற்றுத் தருவதாகக் கூறும் யாரிடமும் அடுத்தடுத்து வரும் OTP-களை பகிர வேண்டாம்.',
        'பணம் எடுக்கப்பட்டிருந்தால், உடனடியாக 1930 என்ற தேசிய உதவி எண்ணை அழைக்கவும்.'
      ],
      hi: [
        'तुरंत अपनी बैंक हेल्पलाइन पर कॉल करें और नेटबैंकिंग व डेबिट कार्ड को ब्लॉक करने का अनुरोध करें।',
        'अपने यूपीआई ऐप (GPay, PhonePe, Paytm) में जाकर अपना यूपीआई पिन तुरंत रीसेट करें।',
        'पैसे वापस दिलाने का दावा करने वाले किसी भी कॉलर के साथ कोई नया ओटीपी साझा न करें।',
        'यदि पैसे कट चुके हैं, तो तुरंत राष्ट्रीय हेल्पलाइन 1930 पर कॉल करें।'
      ],
      te: [
        'వెంటనే మీ బ్యాంక్ కస్టమర్ కేర్‌కు కాల్ చేసి ఖాతా మరియు కార్డ్‌ను బ్లాక్ చేయండి.',
        'మీ UPI యాప్‌లో UPI పిన్‌ను వెంటనే రీసెట్ చేయండి.',
        'ఎవరితోనూ కొత్త OTPలను పంచుకోవద్దు.',
        'డబ్బు కట్ అయితే వెంటనే 1930 నంబర్‌కు కాల్ చేయండి.'
      ]
    },
    officialChannels: ['helpline', 'portal']
  },

  ENTERED_PAYMENT_DETAILS: {
    title: {
      en: 'Entered Debit/Credit Card Details',
      ta: 'டெபிட் அல்லது கிரெடிட் கார்டு விவரங்களை உள்ளிட்டுவிட்டேன்',
      hi: 'डेबिट या क्रेडिट कार्ड का विवरण दर्ज कर दिया',
      te: 'డెబిట్ లేదా క్రెడిట్ కార్డు వివరాలు నమోదు చేసాను'
    },
    urgency: 'critical',
    steps: {
      en: [
        'Open your mobile banking app and immediately toggle OFF international, online, and contactless usage.',
        'Block / hotlist the affected debit or credit card through mobile banking or official bank SMS shortcodes.',
        'Request your bank to issue a replacement card with a new 16-digit PAN and CVV.',
        'Check mini-statement for unauthorized micro-charges or pre-authorization holds.'
      ],
      ta: [
        'உங்கள் வங்கி செயலியைத் திறந்து, சர்வதேச மற்றும் ஆன்லைன் பரிவர்த்தனைகளை உடனடியாக ஆஃப் (OFF) செய்யவும்.',
        'கார்டை உடனடியாக வங்கியின் மொபைல் செயலி அல்லது அதிகாரப்பூர்வ எஸ்எம்எஸ் மூலம் பிளாக் (Block) செய்யவும்.',
        'புதிய அட்டை மற்றும் புதிய CVV எண்ணுடன் புதிய கார்டை வழங்குமாறு வங்கிக்கு கோரிக்கை வைக்கவும்.',
        'உங்கள் கணக்கில் ஏதேனும் அங்கீகரிக்கப்படாத கட்டணங்கள் பிடிக்கப்பட்டுள்ளதா என சோதிக்கவும்.'
      ],
      hi: [
        'अपने मोबाइल बैंकिंग ऐप में जाकर अंतरराष्ट्रीय और ऑनलाइन ट्रांजेक्शन को तुरंत बंद (OFF) करें।',
        'अपने डेबिट या क्रेडिट कार्ड को ऐप या आधिकारिक बैंक एसएमएस कोड के माध्यम से तुरंत ब्लॉक करें।',
        'बैंक से नए 16-अंकों वाले नंबर और सीवीवी के साथ नया कार्ड जारी करने का अनुरोध करें।',
        'अपने स्टेटमेंट में किसी भी अनधिकृत छोटे लेनदेन की जांच करें।'
      ],
      te: [
        'వెంటనే మీ బ్యాంక్ యాప్‌లో ఆన్‌లైన్ మరియు అంతర్జాతీయ లావాదేవీలను ఆఫ్ చేయండి.',
        'బ్యాంక్ యాప్ ద్వారా కార్డును వెంటనే బ్లాక్ చేయండి.',
        'కొత్త కార్డు కోసం దరఖాస్తు చేసుకోండి.',
        'మీ ఖాతా స్టేట్‌మెంట్‌ను తనిఖీ చేయండి.'
      ]
    },
    officialChannels: ['helpline', 'portal']
  },

  APPROVED_PAYMENT_OR_TRANSFERRED: {
    title: {
      en: 'Approved Payment or Transferred Money',
      ta: 'பரிவர்த்தனைக்கு ஒப்புதல் அளித்து பணத்தை அனுப்பிவிட்டேன்',
      hi: 'पेमेंट स्वीकृत कर दिया या पैसे ट्रांसफर कर दिए',
      te: 'డబ్బు ట్రాన్స్‌ఫర్ చేసాను లేదా పేమెంట్ అప్రూవ్ చేసాను'
    },
    urgency: 'critical',
    steps: {
      en: [
        'GOLDEN HOUR ACTION: Call National Helpline 1930 immediately with your transaction UTR / Reference number.',
        'File an incident immediately on https://cybercrime.gov.in under Financial Fraud.',
        'Notify the remitting bank branch manager to initiate a CFCFRMS inter-bank lien/freeze request.',
        'Save transaction screenshots, recipient UPI VPA / Account Number, and chat evidence.'
      ],
      ta: [
        'பொன் நேரம் (Golden Hour): உடனே 1930 என்ற தேசிய உதவி எண்ணை அழைத்து UTR / பரிவர்த்தனை குறிப்பு எண்ணைத் தெரிவிக்கவும்.',
        'https://cybercrime.gov.in தளத்தில் நிதி மோசடி (Financial Fraud) பிரிவில் உடனே புகார் பதிவு செய்யவும்.',
        'பணம் சென்றடைவதைத் தடுக்க உங்கள் வங்கிக் கிளை மேலாளரைத் தொடர்புகொண்டு CFCFRMS மூலம் முடக்கக் கோரவும்.',
        'பரிவர்த்தனை ஸ்கிரீன்ஷாட்கள், பணம் பெற்றவரின் UPI ஐடி / வங்கி கணக்கு மற்றும் அரட்டை ஆதாரங்களை சேமிக்கவும்.'
      ],
      hi: [
        'गोल्डन ऑवर एक्शन: अपने यूटीआर / ट्रांजेक्शन रेफरेंस नंबर के साथ तुरंत 1930 हेल्पलाइन पर कॉल करें।',
        'तुरंत https://cybercrime.gov.in पर वित्तीय धोखाधड़ी (Financial Fraud) के तहत शिकायत दर्ज करें।',
        'अपने बैंक को तुरंत सूचित करें ताकि वह फ्रॉड खाते में पैसे फ्रीज करने के लिए इंटर-बैंक रिक्वेस्ट भेज सके।',
        'लेनदेन का स्क्रीनशॉट, प्राप्तकर्ता का यूपीआई आईडी / बैंक खाता और बातचीत के सबूत सुरक्षित रखें।'
      ],
      te: [
        'గోల్డెన్ అవర్ చర్య: వెంటనే మీ UTR నంబర్‌తో 1930 హెల్ప్‌లైన్‌కు కాల్ చేయండి.',
        'https://cybercrime.gov.in పోర్టల్‌లో వెంటనే ఫిర్యాదు చేయండి.',
        'డబ్బును ఫ్రీజ్ చేయడానికి మీ బ్యాంకును వెంటనే సంప్రదించండి.',
        'లావాదేవీ స్క్రీన్‌షాట్‌లు మరియు UPI ఐడీని భద్రపరచండి.'
      ]
    },
    officialChannels: ['helpline', 'portal']
  },

  INSTALLED_SUSPICIOUS_APP: {
    title: {
      en: 'Installed a Suspicious APK or Application',
      ta: 'சந்தேகத்திற்குரிய APK அல்லது செயலியை நிறுவிவிட்டேன்',
      hi: 'संदिग्ध एपीके या ऐप इंस्टॉल कर लिया',
      te: 'అనుమానాస్పద యాప్ లేదా APK ఇన్‌స్టాల్ చేసాను'
    },
    urgency: 'critical',
    steps: {
      en: [
        'Disconnect phone from internet immediately (turn ON Airplane Mode, turn OFF Wi-Fi).',
        'Reboot phone into Safe Mode (press & hold power, then tap and hold Power Off).',
        'Navigate to Settings > Apps and uninstall the downloaded application.',
        'Go to Settings > Accessibility and verify no unknown apps have screen or keylogging permissions.',
        'If the app cannot be uninstalled or had device admin permissions, perform a Factory Reset.'
      ],
      ta: [
        'உடனடியாக தொலைபேசியை இணையத்திலிருந்து துண்டிக்கவும் (Airplane Mode-ஐ இயக்கவும், Wi-Fi-ஐ அணைக்கவும்).',
        'தொலைபேசியை Safe Mode-ல் மறுதொடக்கம் செய்யவும் (Reboot into Safe Mode).',
        'Settings > Apps சென்று சந்தேகத்திற்குரிய செயலியை அன்இன்ஸ்டால் (Uninstall) செய்யவும்.',
        'Settings > Accessibility சென்று எந்த பயன்பாட்டிற்கும் தேவையற்ற அனுமதிகள் இல்லை என்பதை உறுதிப்படுத்தவும்.',
        'செயலியை நீக்க முடியாவிட்டால், தொலைபேசியை தொழிற்சாலை மீட்டமைப்பு (Factory Reset) செய்யவும்.'
      ],
      hi: [
        'फोन को तुरंत इंटरनेट से डिस्कनेक्ट करें (एरोप्लेन मोड ऑन करें, वाई-फाई बंद करें)।',
        'फोन को सेफ मोड (Safe Mode) में रीस्टार्ट करें।',
        'Settings > Apps में जाकर उस संदिग्ध ऐप को तुरंत अनइंस्टॉल (Uninstall) करें।',
        'Settings > Accessibility में जाकर जांचें कि किसी अज्ञात ऐप के पास परमिशन तो नहीं है।',
        'यदि ऐप अनइंस्टॉल न हो, तो फोन का डेटा बैकअप लेकर फैक्ट्री रीसेट (Factory Reset) करें।'
      ],
      te: [
        'వెంటనే ఫోన్ ఇంటర్నెట్ ఆపివేయండి (ఏరోప్లేన్ మోడ్ ఆన్ చేయండి).',
        'ఫోన్‌ను సేఫ్ మోడ్ (Safe Mode) లో రీస్టార్ట్ చేయండి.',
        'Settings > Apps లోకి వెళ్లి ఆ యాప్‌ను అన్‌ఇన్‌స్టాల్ చేయండి.',
        'Settings > Accessibility లో అనుమానాస్పద అనుమతులను తొలగించండి.',
        'యాప్ తొలగించలేకపోతే ఫోన్‌ను ఫ్యాక్టరీ రీసెట్ చేయండి.'
      ]
    },
    officialChannels: ['telecomChakshu', 'portal']
  },

  GRANTED_REMOTE_ACCESS_OR_ACCESSIBILITY: {
    title: {
      en: 'Granted Remote Access (AnyDesk, TeamViewer, etc.)',
      ta: 'ரிமோட் அணுகல் அல்லது அனுமதி வழங்கிவிட்டேன்',
      hi: 'रिमोट एक्सेस (AnyDesk आदि) की अनुमति दे दी',
      te: 'రిమోట్ యాక్సెస్ అనుమతి ఇచ్చాను'
    },
    urgency: 'critical',
    steps: {
      en: [
        'Disconnect internet connectivity instantly (unplug Ethernet / turn on Airplane Mode).',
        'Terminate the remote session and uninstall AnyDesk, TeamViewer, RustDesk, or QuickSupport.',
        'Restart device in offline mode and check for newly created files or background services.',
        'Call bank from a different telephone to block digital banking until credentials are reset.'
      ],
      ta: [
        'இணைய இணைப்பை உடனே துண்டிக்கவும் (Airplane Mode-ஐ ஆன் செய்யவும்).',
        'ரிமோட் இணைப்பை நிறுத்திவிட்டு, AnyDesk, TeamViewer போன்ற செயலிகளை உடனே அன்இன்ஸ்டால் செய்யவும்.',
        'ஆஃப்லைனில் சாதனத்தை மறுதொடக்கம் செய்து புதிய சந்தேகத்திற்குரிய கோப்புகள் உள்ளதா என சோதிக்கவும்.',
        'வேறொரு தொலைபேசியிலிருந்து வங்கியை அழைத்து நெட்பேங்கிங்கை தற்காலிகமாக முடக்கக் கோரவும்.'
      ],
      hi: [
        'इंटरनेट को तुरंत डिस्कनेक्ट करें (एरोप्लेन मोड ऑन करें)।',
        'रिमोट सेशन को समाप्त करें और AnyDesk, TeamViewer, RustDesk ऐप को तुरंत अनइंस्टॉल करें।',
        'ऑफलाइन रहते हुए डिवाइस को रीस्टार्ट करें और किसी नई संदिग्ध फ़ाइल की जांच करें।',
        'किसी दूसरे फोन से अपने बैंक को कॉल करके डिजिटल बैंकिंग को तुरंत ब्लॉक करवाएं।'
      ],
      te: [
        'వెంటనే ఇంటర్నెట్ ఆపివేయండి.',
        'AnyDesk, TeamViewer వంటి యాప్‌లను వెంటనే అన్‌ఇన్‌స్టాల్ చేయండి.',
        'మరొక ఫోన్ నుండి బ్యాంక్‌కు కాల్ చేసి ఖాతాను బ్లాక్ చేయండి.'
      ]
    },
    officialChannels: ['helpline', 'portal']
  },

  SHARED_IDENTITY_DOCUMENTS: {
    title: {
      en: 'Shared Aadhaar, PAN, or Passport Copy',
      ta: 'ஆதார், பான் அல்லது அடையாள ஆவணங்களைப் பகிர்ந்துவிட்டேன்',
      hi: 'आधार, पैन या पहचान दस्तावेज साझा कर दिए',
      te: 'ఆధార్ లేదా పాన్ వివరాలు పంచుకున్నాను'
    },
    urgency: 'high',
    steps: {
      en: [
        'Log in to https://myaadhaar.uidai.gov.in and immediately LOCK your Aadhaar Biometrics.',
        'Check your telecom SIM connections at DoT TAFCOP portal (https://tafcop.sancharsaathi.gov.in) to verify no unauthorized mobile connections were taken under your Aadhaar.',
        'Pull a free credit report (CIBIL, Experian, CRIF) to verify no fraudulent loan inquiries were initiated.',
        'File an informative report on cybercrime.gov.in to protect against future identity misuse.'
      ],
      ta: [
        'https://myaadhaar.uidai.gov.in தளத்தில் நுழைந்து உடனடியாக உங்கள் ஆதார் பயோமெட்ரிக்ஸை லாக் (Lock) செய்யவும்.',
        'DoT TAFCOP தளத்திற்குச் சென்று உங்கள் பெயரில் அங்கீகரிக்கப்படாத புதிய சிம் கார்டுகள் வாங்கப்பட்டுள்ளதா என சரிபார்க்கவும்.',
        'உங்கள் பெயரில் ஏதேனும் போலி கடன்கள் கோரப்பட்டுள்ளதா என CIBIL கிரெடிட் அறிக்கையை சரிபார்க்கவும்.',
        'எதிர்கால தவறான பயன்பாட்டில் இருந்து பாதுகாக்க cybercrime.gov.in தளத்தில் தகவல் பதிவு செய்யவும்.'
      ],
      hi: [
        'तुरंत https://myaadhaar.uidai.gov.in पर जाएं और अपना आधार बायोमेट्रिक लॉक (Lock) करें।',
        'DoT TAFCOP पोर्टल पर जाकर चेक करें कि आपके आधार पर कोई अज्ञात मोबाइल नंबर तो जारी नहीं हुआ है।',
        'सिबिल (CIBIL) रिपोर्ट चेक करें कि आपके नाम पर कोई फर्जी लोन तो नहीं लिया जा रहा।',
        'भविष्य में दुरुपयोग से बचाव के लिए cybercrime.gov.in पर एक सूचनात्मक रिपोर्ट दर्ज करें।'
      ],
      te: [
        'వెంటనే https://myaadhaar.uidai.gov.in లో మీ ఆధార్ బయోమెట్రిక్స్‌ను లాక్ చేయండి.',
        'TAFCOP పోర్టల్‌లో మీ పేరు మీద కొత్త సిమ్‌లు ఉన్నాయేమో తనిఖీ చేయండి.',
        'మీ CIBIL క్రెడిట్ రిపోర్ట్‌ను తనిఖీ చేయండి.'
      ]
    },
    officialChannels: ['aadhaarLock', 'telecomChakshu', 'portal']
  },

  EXTORTION_OR_DIGITAL_ARREST: {
    title: {
      en: 'Faced Digital Arrest / Police Coercion Threat',
      ta: 'டிஜிட்டல் கைது அல்லது போலீஸ் மிரட்டலை எதிர்கொண்டேன்',
      hi: 'डिजिटल अरेस्ट या पुलिस धमकी का सामना किया',
      te: 'డిజిటల్ అరెస్ట్ బెదిరింపును ఎదుర్కొన్నాను'
    },
    urgency: 'critical',
    steps: {
      en: [
        'REMEMBER: Indian Police, CBI, ED, and Customs NEVER arrest people or hold trials over WhatsApp/Skype video calls. "Digital Arrest" is 100% fake.',
        'Hang up the call immediately. Block the phone numbers on WhatsApp and phone dialer.',
        'Do not isolate yourself. Talk immediately to family members, friends, or local police.',
        'NEVER transfer money to any "RBI Safe Account" or "Verification Account" — no such government accounts exist.',
        'Call 1930 immediately to register an extortion attempt report with law enforcement.'
      ],
      ta: [
        'நினைவில் கொள்க: இந்திய காவல் துறை, சிபிஐ அல்லது சுங்கத்துறை ஒருபோதும் வாட்ஸ்அப் அல்லது ஸ்கைப் வீடியோ காலில் கைது செய்யாது. டிஜிட்டல் கைது என்பது 100% போலி.',
        'அழைப்பை உடனடியாக துண்டிக்கவும். வாட்ஸ்அப் மற்றும் போனில் அந்த எண்களை முடக்கவும் (Block).',
        'உங்களை தனிமைப்படுத்திக் கொள்ள வேண்டாம். குடும்பத்தினர் அல்லது நண்பர்களிடம் உடனடியாகப் பேசுங்கள்.',
        '"ஆர்பிஐ பாதுகாப்புக் கணக்கு" என்று கூறி பணம் அனுப்பக் கோரினால் அனுப்பாதீர்கள் — அப்படிப்பட்ட கணக்குகள் எதுவும் இல்லை.',
        'காவல்துறையில் மிரட்டல் குறித்து புகார் அளிக்க உடனே 1930 எண்ணை அழைக்கவும்.'
      ],
      hi: [
        'याद रखें: भारतीय पुलिस, सीबीआई, ईडी या कस्टम विभाग कभी भी व्हाट्सएप/स्काइप वीडियो कॉल पर गिरफ्तारी नहीं करते। "डिजिटल अरेस्ट" पूरी तरह से फर्जी है।',
        'कॉल तुरंत काट दें। व्हाट्सएप और फोन पर उन नंबरों को ब्लॉक करें।',
        'खुद को कमरे में बंद न करें। तुरंत अपने परिवार के सदस्यों, दोस्तों या नजदीकी पुलिस से बात करें।',
        'किसी भी "आरबीआई सुरक्षित खाते" में पैसे ट्रांसफर न करें — ऐसा कोई खाता नहीं होता।',
        'जबरन वसूली के प्रयास की रिपोर्ट दर्ज कराने के लिए तुरंत 1930 पर कॉल करें।'
      ],
      te: [
        'గుర్తుంచుకోండి: పోలీసులు ఎప్పుడూ వీడియో కాల్స్‌లో అరెస్ట్ చేయరు. డిజిటల్ అరెస్ట్ పూర్తిగా మోసం.',
        'వెంటనే కాల్ కట్ చేసి నంబర్‌ను బ్లాక్ చేయండి.',
        'కుటుంబ సభ్యులకు లేదా పోలీసులకు వెంటనే చెప్పండి.',
        'ఎలాంటి "ఆర్బీఐ ఖాతా"కు డబ్బు పంపవద్దు.',
        'వెంటనే 1930 కి కాల్ చేసి ఫిర్యాదు చేయండి.'
      ]
    },
    officialChannels: ['helpline', 'portal']
  },

  UNCERTAIN_WHAT_HAPPENED: {
    title: {
      en: 'Uncertain or Confused What Happened',
      ta: 'என்ன நடந்தது என்று உறுதியாகத் தெரியவில்லை',
      hi: 'स्पष्ट नहीं है कि वास्तव में क्या हुआ',
      te: 'ఏం జరిగిందో స్పష్టంగా తెలియడం లేదు'
    },
    urgency: 'medium',
    steps: {
      en: [
        'Stop all ongoing digital actions. Do not approve pending notifications or click new links.',
        'Review your bank mini-statements and payment app passbooks for unexpected transactions.',
        'Show the interaction to a digitally literate family member or trusted local friend.',
        'Call the official 1930 cyber fraud helpline if you suspect any compromise of your accounts.'
      ],
      ta: [
        'அனைத்து டிஜிட்டல் செயல்பாடுகளையும் தற்காலிகமாக நிறுத்துங்கள். புதிய இணைப்புகளைக் கிளிக் செய்ய வேண்டாம்.',
        'எதிர்பாராத பரிவர்த்தனைகள் ஏதேனும் உள்ளதா என உங்கள் வங்கி அறிக்கைகளை சரிபார்க்கவும்.',
        'நம்பகமான குடும்ப உறுப்பினர் அல்லது நண்பரிடம் இந்த தகவலைக் காட்டி ஆலோசிக்கவும்.',
        'ஏதேனும் சந்தேகம் இருந்தால் 1930 என்ற உதவி எண்ணை அழைத்து ஆலோசனை பெறவும்.'
      ],
      hi: [
        'सभी चालू डिजिटल गतिविधियों को तुरंत रोकें। किसी भी नए लिंक पर क्लिक न करें।',
        'किसी अप्रत्याशित लेनदेन के लिए अपने बैंक पासबुक और पेमेंट ऐप को चेक करें।',
        'किसी जानकार पारिवारिक सदस्य या मित्र को यह घटना दिखाएं।',
        'यदि कोई अनहोनी की आशंका हो, तो राष्ट्रीय साइबर हेल्पलाइन 1930 पर कॉल करें।'
      ],
      te: [
        'అన్ని డిజిటల్ చర్యలను తాత్కాలికంగా ఆపండి.',
        'మీ బ్యాంక్ ఖాతా స్టేట్‌మెంట్‌ను తనిఖీ చేయండి.',
        'నమ్మకమైన స్నేహితుడు లేదా కుటుంబ సభ్యులతో మాట్లాడండి.',
        'అనుమానం ఉంటే 1930 నంబర్‌కు కాల్ చేయండి.'
      ]
    },
    officialChannels: ['helpline']
  }
};

/**
 * Redacts sensitive credentials (PAN, Aadhaar, OTP, PIN, Passwords, Credit Card numbers)
 * from text or object payloads before generating evidence exports.
 *
 * @param {string} text - Raw content that might contain sensitive citizen secrets
 * @returns {string} Sanitized string with secrets masked
 */
export function sanitizeSecrets(text) {
  if (!text || typeof text !== 'string') return '';

  let sanitized = text;

  // 1. Redact 13-19 digit Credit/Debit Card PANs (keep last 4 digits)
  sanitized = sanitized.replace(/\b(?:\d[ -]*?){13,19}\b/g, (match) => {
    const digitsOnly = match.replace(/\D/g, '');
    if (digitsOnly.length >= 13 && digitsOnly.length <= 19) {
      const last4 = digitsOnly.slice(-4);
      return `****-****-****-${last4}`;
    }
    return match;
  });

  // 2. Redact 12-digit Indian Aadhaar Numbers (keep last 4)
  sanitized = sanitized.replace(/\b\d{4}\s?\d{4}\s?(\d{4})\b/g, 'XXXX-XXXX-$1');

  // 3. Redact 3-4 digit CVV/CVC codes
  sanitized = sanitized.replace(/(cvv|cvc|security\s*code)[\s:=]+([0-9]{3,4})/gi, '$1: [REDACTED_CVV]');

  // 4. Redact 4 or 6 digit OTP / UPI PINs
  sanitized = sanitized.replace(/(otp|pin|upi\s*pin|code)[\s:=]+([0-9]{4,6})\b/gi, '$1: [REDACTED_PIN]');

  // 5. Redact cleartext password fields
  sanitized = sanitized.replace(/(password|passwd|pwd)[\s:=]+([^\s,;]+)/gi, '$1: [REDACTED_PASSWORD]');

  return sanitized;
}

/**
 * Builds a user-controlled local Evidence Receipt formatted for cybercrime reporting.
 *
 * @param {object} params
 * @param {string} params.scanId
 * @param {string} params.rawInput
 * @param {object} params.verdict
 * @param {string} [params.lang='en']
 * @param {object} [params.incidentDetails={}]
 * @returns {{
 *   receiptId: string,
 *   generatedAt: string,
 *   sanitizedSummary: string,
 *   technicalEvidence: object,
 *   markdownExport: string,
 *   jsonExport: string
 * }}
 */
export function generateEvidenceReceipt(params) {
  const lang = params.lang || 'en';
  const receiptId = `REC-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
  const now = new Date().toISOString();

  const sanitizedInput = sanitizeSecrets(params.rawInput || '');
  const signals = params.verdict?.evidence || params.verdict?.signals || [];
  const score = params.verdict?.riskScore ?? params.verdict?.score ?? 0;
  const classification = params.verdict?.riskClassification || (score >= 70 ? 'HIGH_RISK' : 'CAUTION');

  const technicalEvidence = {
    receiptId,
    timestamp: now,
    scanId: params.verdict?.scanId || 'unknown',
    riskClassification: classification,
    riskScore: score,
    inputSnippetSanitized: sanitizedInput.slice(0, 2000),
    forensicSignals: signals.map(s => ({
      id: s.id || s,
      description: s.description || s.reason || 'Forensic detection signal'
    })),
    officialReportingChecklist: [
      'Call 1930 immediately to freeze fraudulent transfers.',
      'Log into https://cybercrime.gov.in and attach this receipt.',
      'Notify your bank branch with transaction reference number / UTR.'
    ]
  };

  const markdownExport = `# VERITY 2.0 — Citizen Cyber Incident Evidence Receipt
**Receipt ID**: \`${receiptId}\`  
**Generated At**: ${now}  
**Risk Assessment**: **${classification}** (Score: ${score}/100)  
**Verification Engine**: Pure On-Device Local Inspection  

---

### 1. Incident Target & Input (Sanitized)
> **Note**: For your privacy, passwords, OTPs, Aadhaar, and full card numbers have been automatically redacted.

\`\`\`text
${sanitizedInput}
\`\`\`

---

### 2. Forensic Findings & Technical Observations
${signals.length > 0
  ? signals.map(s => `- **${s.id || s}**: ${sanitizeSecrets(s.description || s.reason || 'Detected forensic anomaly')}`).join('\n')
  : '- No anomalous threat signatures detected by local heuristic rules.'}

---

### 3. Recommended Official Actions for Victim
1. **National Cyber Crime Helpline**: Call **1930** immediately if money was transferred.
2. **Online Complaint**: Submit this evidence at [cybercrime.gov.in](https://cybercrime.gov.in).
3. **Bank Action**: Contact your bank customer service to dispute unauthorized charges or freeze compromised cards/accounts.

*Generated locally on user device. Confidential citizen evidence record.*
`;

  return {
    receiptId,
    generatedAt: now,
    sanitizedSummary: sanitizedInput,
    technicalEvidence,
    markdownExport,
    jsonExport: JSON.stringify(technicalEvidence, null, 2),
    secretsRedacted: sanitizedInput !== (params.rawInput || '')
  };
}

/**
 * Retrieves the specific recovery decision tree for an incident type and language.
 *
 * @param {string} incidentType
 * @param {string} [lang='en']
 * @returns {object}
 */
export function getRecoveryGuide(incidentType, lang = 'en') {
  const guide = RECOVERY_GUIDES[incidentType] || RECOVERY_GUIDES.UNCERTAIN_WHAT_HAPPENED;
  const targetLang = RECOVERY_GUIDES[incidentType]?.steps[lang] ? lang : 'en';

  const channels = (guide.officialChannels || []).map(key => OFFICIAL_RECOVERY_REGISTRY[key]).filter(Boolean);

  return {
    incidentType,
    urgency: guide.urgency,
    title: guide.title[targetLang] || guide.title.en,
    steps: guide.steps[targetLang] || guide.steps.en,
    officialChannels: channels,
    primaryHelpline: OFFICIAL_RECOVERY_REGISTRY.helpline
  };
}

export default {
  OFFICIAL_RECOVERY_REGISTRY,
  INCIDENT_TYPES,
  RECOVERY_GUIDES,
  sanitizeSecrets,
  generateEvidenceReceipt,
  getRecoveryGuide
};
