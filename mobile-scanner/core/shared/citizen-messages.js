/**
 * shared/citizen-messages.js — Plain-language citizen advisories & UI strings
 *
 * Supported Indian languages:
 * - en: English
 * - ta: தமிழ் (Tamil)
 * - hi: हिन्दी (Hindi)
 * - te: తెలుగు (Telugu)
 *
 * Designed with zero browser extension APIs and zero DOM dependencies for universal portability
 * across extension UI, background service workers, and mobile PWAs.
 */

export const LANGS = [
  { code: 'en', label: 'English', short: 'EN' },
  { code: 'ta', label: 'தமிழ்', short: 'தமிழ்' },
  { code: 'hi', label: 'हिन्दी', short: 'हिं' },
  { code: 'te', label: 'తెలుగు', short: 'తె' }
];

export const STATUS = {
  en: {
    safe: 'SAFE WEBSITE',
    caution: 'BE CAREFUL',
    danger: 'DANGER: SCAM DETECTED'
  },
  ta: {
    safe: 'பாதுகாப்பான தளம்',
    caution: 'கவனமாக இருங்கள்',
    danger: 'ஆபத்து: மோசடி கண்டறியப்பட்டது'
  },
  hi: {
    safe: 'सुरक्षित वेबसाइट',
    caution: 'सावधान रहें',
    danger: 'खतरा: धोखाधड़ी पकड़ी गई'
  },
  te: {
    safe: 'సురక్షితమైన వెబ్‌సైట్',
    caution: 'జాగ్రత్తగా ఉండండి',
    danger: 'ప్రమాదం: మోసం గుర్తించబడింది'
  }
};

export const UI = {
  en: {
    checkButton: 'Check Link / Text',
    pastePlaceholder: 'Paste suspicious WhatsApp link, SMS, or message here...',
    whyTitle: 'How did we catch this?',
    backToSafety: 'Take Me to Safety',
    goldenRuleTitle: 'Golden Safety Rule',
    currentSite: 'Current Website',
    quickChecker: 'Quick WhatsApp / Link Checker',
    noThreatFound: 'No threat detected. Looks safe.',
    advancedDetails: 'Advanced Technical Details',
    nothingToCheck: 'Please enter a URL or message to scan.',
    privacyLine: 'Everything is checked on your device. Nothing is uploaded.'
  },
  ta: {
    checkButton: 'இணைப்பைச் சரிபார்க்கவும்',
    pastePlaceholder: 'சந்தேகத்திற்குரிய வாட்ஸ்அப் இணைப்பு அல்லது செய்தியை இங்கே ஒட்டவும்...',
    whyTitle: 'இதை நாங்கள் எவ்வாறு கண்டுபிடித்தோம்?',
    backToSafety: 'என்னை பாதுகாப்பான இடத்திற்கு அழைத்துச் செல்லவும்',
    goldenRuleTitle: 'தங்க பாதுகாப்பு விதி',
    currentSite: 'தற்போதைய தளம்',
    quickChecker: 'விரைவு வாட்ஸ்அப் / இணைப்பு சோதனையாளர்',
    noThreatFound: 'அச்சுறுத்தல் எதுவும் இல்லை. பாதுகாப்பாக உள்ளது.',
    advancedDetails: 'மேம்பட்ட தொழில்நுட்ப விவரங்கள்',
    nothingToCheck: 'சரிபார்க்க ஒரு இணைப்பு அல்லது செய்தியை உள்ளிடவும்.',
    privacyLine: 'அனைத்தும் உங்கள் சாதனத்திலேயே சரிபார்க்கப்படுகிறது. எதுவும் பதிவேற்றப்படவில்லை.'
  },
  hi: {
    checkButton: 'लिंक / मैसेज जांचें',
    pastePlaceholder: 'संदिग्ध व्हाट्सएप लिंक, SMS या मैसेज यहाँ पेस्ट करें...',
    whyTitle: 'हमने इस धोखाधड़ी को कैसे पकड़ा?',
    backToSafety: 'मुझे सुरक्षित स्थान पर ले जाएं',
    goldenRuleTitle: 'गोल्डन सुरक्षा नियम',
    currentSite: 'वर्तमान वेबसाइट',
    quickChecker: 'त्वरित व्हाट्सएप / लिंक चेकर',
    noThreatFound: 'कोई खतरा नहीं मिला। सुरक्षित प्रतीत होता है।',
    advancedDetails: 'विस्तृत तकनीकी जानकारी',
    nothingToCheck: 'कृपया जांचने के लिए एक लिंक या मैसेज दर्ज करें।',
    privacyLine: 'सब कुछ आपके डिवाइस पर ही जाँचा जाता है। कुछ भी अपलोड नहीं होता।'
  },
  te: {
    checkButton: 'లింక్ / మెసేజ్ తనిఖీ చేయండి',
    pastePlaceholder: 'అనుమానాస్పద వాట్సాప్ లింక్, SMS లేదా సందేశాన్ని ఇక్కడ పేస్ట్ చేయండి...',
    whyTitle: 'మేము ఈ మోసాన్ని ఎలా పట్టుకున్నాము?',
    backToSafety: 'నన్ను సురక్షిత ప్రదేశానికి తీసుకెళ్లండి',
    goldenRuleTitle: 'గోల్డెన్ సేఫ్టీ రూల్', // REVIEW-NATIVE: colloquial Telugu safety heading
    currentSite: 'ప్రస్తుత వెబ్‌సైట్',
    quickChecker: 'త్వరిత వాట్సాప్ / లింక్ చెకర్', // REVIEW-NATIVE: colloquial Telugu quick checker
    noThreatFound: 'ఎలాంటి ప్రమాదం గుర్తించబడలేదు. సురక్షితంగా ఉంది.',
    advancedDetails: 'మరిన్ని సాంకేతిక వివరాలు',
    nothingToCheck: 'దయచేసి స్కాన్ చేయడానికి లింక్ లేదా సందేశాన్ని నమోదు చేయండి.',
    privacyLine: 'అంతా మీ పరికరంలోనే తనిఖీ చేయబడుతుంది. ఏదీ అప్‌లోడ్ చేయబడదు.'
  }
};

export const GOLDEN_RULES = {
  upi: {
    en: 'Never enter your UPI PIN to receive money. UPI PIN is only entered to send money.',
    ta: 'பணம் பெற ஒருபோதும் UPI பின்னை உள்ளிடாதீர்கள். பணம் அனுப்ப மட்டுமே UPI பின் பயன்படுகிறது.',
    hi: 'पैसे प्राप्त करने के लिए कभी भी UPI पिन न डालें। UPI पिन केवल पैसे भेजने के लिए होता है।',
    te: 'డబ్బు అందుకోవడానికి ఎప్పుడూ UPI పిన్ నమోదు చేయవద్దు. UPI పిన్ డబ్బు పంపడానికి మాత్రమే.'
  },
  digital_arrest: {
    en: 'Police, CBI, or Customs never arrest anyone over video calls or demand money online. Disconnect immediately.',
    ta: 'காவல்துறை அல்லது CBI ஒருபோதும் வீடியோ காலில் கைது செய்ய மாட்டார்கள், ஆன்லைனில் பணம் கேட்க மாட்டார்கள். உடனே இணைப்பைத் துண்டிக்கவும்.',
    hi: 'पुलिस, CBI या कस्टम्स कभी वीडियो कॉल पर गिरफ़्तार नहीं करते और न ही ऑनलाइन पैसे मांगते हैं। तुरंत कॉल काटें।',
    te: 'పోలీసులు లేదా CBI ఎప్పుడూ వీడియో కాల్స్‌లో అరెస్ట్ చేయరు, ఆన్‌లైన్‌లో డబ్బు అడగరు. వెంటనే కాల్ కట్ చేయండి.'
  },
  apk: {
    en: 'Never install .apk files received on WhatsApp or SMS. Only install apps from the official Google Play Store.',
    ta: 'வாட்ஸ்அப் அல்லது SMS மூலம் வரும் .apk கோப்புகளை நிறுவ வேண்டாம். கூகுள் பிளே ஸ்டோரிலிருந்து மட்டுமே பயன்பாடுகளைப் பதிவிறக்கவும்.',
    hi: 'व्हाट्सएप या SMS पर मिली .apk फाइलों को कभी इंस्टॉल न करें। ऐप हमेशा गूगल प्ले स्टोर से ही लें।',
    te: 'వాట్సాప్ లేదా SMS లో వచ్చే .apk ఫైళ్లను ఎప్పుడూ ఇన్‌స్టాల్ చేయవద్దు. అధికారిక గూగుల్ ప్లే స్టోర్ నుండి మాత్రమే యాప్‌లను పొందండి.'
  },
  otp_password: {
    en: 'Bank officials will never ask for your OTP or password. Never share them with anyone on calls or messages.',
    ta: 'வங்கி அதிகாரிகள் ஒருபோதும் உங்கள் OTP அல்லது கடவுச்சொல்லைக் கேட்க மாட்டார்கள். அவற்றை யாருடனும் பகிராதீர்கள்.',
    hi: 'बैंक अधिकारी कभी भी आपका OTP या पासवर्ड नहीं मांगते। इसे किसी के साथ भी शेयर न करें।',
    te: 'బ్యాంక్ అధికారులు ఎప్పుడూ మీ OTP లేదా పాస్‌వర్డ్ అడగరు. వాటిని ఎవరితోనూ పంచుకోవద్దు.'
  },
  generic: {
    en: 'Stop and verify with your family or official customer care before clicking urgent links or making payments.',
    ta: 'அவசர இணைப்புகளைக் கிளிக் செய்வதற்கோ பணம் செலுத்துவதற்கோ முன் குடும்பத்தினருடன் சரிபார்க்கவும்.',
    hi: 'जल्दबाजी में किसी लिंक पर क्लिक करने या पैसे भेजने से पहले अपने परिवार या आधिकारिक हेल्पलाइन से पुष्टि करें।',
    te: 'అత్యవసర లింక్‌లపై క్లిక్ చేయడానికి లేదా చెల్లింపులు చేయడానికి ముందు కుటుంబ సభ్యులతో మాట్లాడి నిర్ధారించుకోండి.'
  }
};

export const REASON_PLAIN = {
  SIG_DIGITAL_ARREST_EXTORTION: {
    en: 'Fake police or CBI extortion scam threatening arrest over video call.',
    ta: 'வீடியோ அழைப்பில் கைது செய்வதாக மிரட்டும் போலி காவல்துறை அல்லது CBI மிரட்டல் மோசடி.',
    hi: 'वीडियो कॉल पर गिरफ्तारी की धमकी देकर वसूली करने वाला फर्जी पुलिस या CBI स्कैम।',
    te: 'వీడియో కాల్‌లో అరెస్ట్ చేస్తామని బెదిరించి డబ్బులు వసూలు చేసే నకిలీ పోలీసు లేదా CBI మోసం.'
  },
  SIG_MALICIOUS_APK_DROPPER: {
    en: 'Dangerous Android app (.apk) that steals bank OTPs and personal messages.',
    ta: 'வங்கி OTP மற்றும் தனிப்பட்ட செய்திகளைத் திருடும் ஆபத்தான Android (.apk) செயலி.',
    hi: 'बैंक OTP और निजी मैसेज चुराने वाला खतरनाक एंड्रॉइड ऐप (.apk)।',
    te: 'బ్యాంక్ OTPలు మరియు వ్యక్తిగత సందేశాలను దొంగిలించే ప్రమాదకరమైన ఆండ్రాయిడ్ యాప్ (.apk).'
  },
  SIG_ILLEGAL_WEB_PIN_COLLECTION: {
    en: 'Unverified web page illegally asking for your confidential UPI PIN or ATM PIN.',
    ta: 'உங்கள் ரகசிய UPI பின் அல்லது ATM பின்னை சட்டவிரோதமாகக் கேட்கும் போலி தளம்.',
    hi: 'अवैध रूप से आपका गोपनीय UPI पिन या ATM पिन मांगने वाला असत्यापित वेब पेज।',
    te: 'మీ రహస్య UPI పిన్ లేదా ATM పిన్‌ను అక్రమంగా అడుగుతున్న నకిలీ వెబ్ పేజీ.'
  },
  SIG_UPI_QR_COLLECT_TRAP: {
    en: 'Fake cashback or lottery lure tricking you into scanning a QR code that deducts money.',
    ta: 'பணத்தை கழிக்கும் QR குறியீட்டை ஸ்கேன் செய்ய வைக்கும் போலி கேஷ்பேக் பொறி.',
    hi: 'पैसे काटने वाले QR कोड को स्कैन करवाने वाला फर्जी कैशबैक या इनाम का जाल।',
    te: 'డబ్బులు కట్ చేసే QR కోడ్‌ని స్కాన్ చేయించే నకిలీ క్యాష్‌బ్యాక్ లేదా బహుమతి ట్రాప్.'
  },
  SIG_ONLINE_ENTITY_DOMAIN_MISMATCH: {
    en: 'Public registry mismatch: Brand claims do not match its official verified domain.',
    ta: 'பொதுப் பதிவு முரண்பாடு: பிராண்ட் உரிமை கோரல் அதன் அதிகாரப்பூர்வ சரிபார்க்கப்பட்ட தளத்துடன் பொருந்தவில்லை.',
    hi: 'सार्वजनिक सत्यापन बेमेल: वेबसाइट का दावा उसके आधिकारिक सत्यापित डोमेन से मेल नहीं खाता।',
    te: 'పబ్లిక్ రిజిస్ట్రీ అసమతుల్యత: బ్రాండ్ వాదనలు దాని అధికారిక ధృవీకరించబడిన డొమైన్‌తో సరిపోలడం లేదు.'
  },
  SIG_SECV_PSYCHOLINGUISTIC_CONVERGENCE: {
    en: 'High-pressure cyber fraud message coercing confidential PIN, OTP, or video calls.',
    ta: 'ரகசிய PIN, OTP அல்லது வீடியோ அழைப்பை வற்புறுத்தி ஏமாற்றும் அதிதீவிர உளவியல் மோசடி செய்தி.',
    hi: 'गोपनीय पिन, ओटीपी या वीडियो कॉल के लिए दबाव बनाने वाला उच्च-स्तरीय धोखाधड़ी संदेश।',
    te: 'రహస్య పిన్, ఓటీపీ లేదా వీడియో కాల్ కోసం ఒత్తిడి తెచ్చే మోసపూరిత సైబర్ సందేశం.'
  },
  SIG_AUTONOMOUS_BRAND_IDENTITY_MISMATCH: {
    en: 'Website claims to be an official bank, fintech, or institution on an unauthorized domain.',
    ta: 'அங்கீகரிக்கப்படாத முகவரியில் வங்கி அல்லது நிதி நிறுவனத்தின் பெயரைப் பயன்படுத்தி ஏமாற்றும் தளம்.',
    hi: 'अनधिकृत डोमेन पर आधिकारिक बैंक, फिनटेक या संस्थान होने का झूठा दावा करने वाली वेबसाइट।',
    te: 'అనధికారిక డొమైన్‌లో అధికారిక బ్యాంక్ లేదా ఫిన్‌టెక్ సంస్థగా నటిస్తూ మోసగించే వెబ్‌సైట్.'
  },
  SIG_PHISHSTATS_LIVE_FEED_HIT: {
    en: 'Website confirmed as an active phishing attack on global threat intelligence feeds.',
    ta: 'உலகளாவிய அச்சுறுத்தல் தரவுத்தளத்தில் இந்த தளம் நேரடி மோசடி தளமாக பட்டியலிடப்பட்டுள்ளது.',
    hi: 'वैश्विक साइबर सुरक्षा थ्रेट फीड पर सक्रिय फ़िशिंग वेबसाइट के रूप में पुष्टि की गई।',
    te: 'గ్లోబల్ సైబర్ సెక్యూరిటీ థ్రెట్ ఫీడ్‌లలో క్రియాశీల ఫిషింగ్ వెబ్‌సైట్‌గా నిర్ధారించబడింది.'
  },
  SIG_MISSING_DMARC_CREDENTIAL_TRAP: {
    en: 'Cryptographic DNS check failed: Fake institutional domain lacks email and identity security.',
    ta: 'கிரிப்டோகிராஃபிக் DNS தோல்வி: நிறுவன அடையாளம் கூறும் போலி தளத்தில் DMARC பாதுகாப்பு இல்லை.',
    hi: 'क्रिप्टोग्राफ़िक डीएनएस जांच विफल: संस्थान का दावा करने वाले फर्जी डोमेन पर DMARC सुरक्षा नहीं है।',
    te: 'క్రిప్టోగ్రాఫిక్ DNS విఫలమైంది: సంస్థగా పేర్కొంటున్న నకిలీ డొమైన్‌లో DMARC భద్రత లేదు.'
  },
  SIG_TYPOSQUATTING: {
    en: 'Deceptive website name designed to look like a trusted official brand.',
    ta: 'நம்பகமான அதிகாரப்பூர்வ நிறுவனத்தின் பெயரைப் போல ஏமாற்றும் வகையில் அமைக்கப்பட்ட போலி தளம்.',
    hi: 'विश्वसनीय आधिकारिक ब्रांड जैसा दिखने के लिए बनाया गया भ्रामक वेबसाइट नाम।',
    te: 'నమ్మకమైన అధికారిక బ్రాండ్ లాగా కనిపించేలా మోసపూరితంగా రూపొందించిన నకిలీ వెబ్‌సైట్ పేరు.'
  },
  SIG_HOMOGRAPH_ATTACK: {
    en: 'Lookalike domain name using foreign alphabet characters to disguise a fake website.',
    ta: 'போலி தளத்தை மறைக்க வேற்று மொழி எழுத்துக்களைப் பயன்படுத்தும் ஏமாற்று முகவரி.',
    hi: 'फर्जी वेबसाइट को छिपाने के लिए विदेशी अक्षरों का उपयोग करने वाला धोखेबाज नाम।',
    te: 'నకిలీ వెబ్‌సైట్‌ను కప్పిపుచ్చడానికి విదేశీ అక్షరాలను ఉపయోగించే మోసపూరిత డొమైన్ పేరు.'
  },
  RULE_BRAND_NAME_WRONG_DOMAIN: {
    en: 'Website mentions a trusted company name but is not their official web address.',
    ta: 'நம்பகமான நிறுவனத்தின் பெயரைக் குறிப்பிட்டாலும் இது அவர்களின் அதிகாரப்பூர்வ தளம் அல்ல.',
    hi: 'वेबसाइट पर किसी प्रसिद्ध कंपनी का नाम है, लेकिन यह उनका असली पता नहीं है।',
    te: 'వెబ్‌సైట్ ప్రముఖ కంపెనీ పేరును ఉపయోగిస్తోంది కానీ ఇది వారి అధికారిక సైట్ కాదు.'
  },
  RULE_IP_BASED_URL: {
    en: 'Website uses a raw computer IP number instead of a verified registered domain name.',
    ta: 'அங்கீகரிக்கப்பட்ட இணைய முகவரிக்கு பதிலாக எண் வடிவிலான கணினி முகவரியைப் (IP) பயன்படுத்துகிறது.',
    hi: 'वेबसाइट असली डोमेन नाम के बजाय सीधे कंप्यूटर IP नंबर का उपयोग कर रही है।',
    te: 'వెబ్‌సైట్ సరైన డొమైన్ పేరుకు బదులుగా నేరుగా కంప్యూటర్ IP నంబర్‌ను ఉపయోగిస్తోంది.'
  },
  RULE_MISSING_HTTPS: {
    en: 'Insecure connection lacking standard security encryption.',
    ta: 'பாதுகாப்பான குறியாக்கம் இல்லாத பாதுகாப்பற்ற இணைய இணைப்பு.',
    hi: 'असुरक्षित कनेक्शन जिसमें मानक सुरक्षा एन्क्रिप्शन नहीं है।',
    te: 'ప్రామాణిక భద్రతా ఎన్‌క్రిప్షన్ లేని అసురక్షిత కనెక్షన్.'
  },
  SIG_AITM_REVERSE_PROXY_PHISH: {
    en: 'Adversary-in-the-Middle reverse proxy attempting to bypass multi-factor authentication (MFA).',
    ta: 'உங்கள் இருபடி அங்கீகாரத்தை (OTP/MFA) ஏமாற்ற முயலும் அதிநவீன போலி உள்நுழைவு தளம்.',
    hi: 'टू-फैक्टर प्रमाणीकरण (OTP/MFA) को बायपास करने की कोशिश करने वाला फर्जी लॉगिन पेज।',
    te: 'మీ టూ-ఫ్యాక్టర్ ప్రామాణీకరణను (OTP/MFA) దాటవేయడానికి ప్రయత్నిస్తున్న నకిలీ లాగిన్ పేజీ.' // REVIEW-NATIVE: colloquial Telugu phrasing for MFA bypass
  },
  SIG_FREE_HOST_CREDENTIAL_PHISH: {
    en: 'Phishing login page hosted on a free developer platform or tunnel.',
    ta: 'இலவச இணைய தளத்தில் அமைக்கப்பட்ட போலி உள்நுழைவு தளம்.',
    hi: 'फ्री होस्टिंग प्लेटफॉर्म या टनल पर बना फर्जी फिशिंग लॉगिन पेज।',
    te: 'ఉచిత హోస్టింగ్ ప్లాట్‌ఫామ్‌లో రూపొందించిన నకిలీ లాగిన్ పేజీ.'
  },
  SIG_DOM_BRAND_IMPERSONATION: {
    en: 'Website title claims to be an official bank or government agency on an unauthorized domain.',
    ta: 'அங்கீகரிக்கப்படாத முகவரியில் அதிகாரப்பூர்வ வங்கி அல்லது அரசு தளம் போல் வேடமிடுகிறது.',
    hi: 'अनधिकृत डोमेन पर आधिकारिक बैंक या सरकारी एजेंसी होने का झूठा दावा।',
    te: 'అనధికారిక డొమైన్‌లో అధికారిక బ్యాంక్ లేదా ప్రభుత్వ సంస్థగా నటిస్తోంది.'
  },
  SIG_DECEPTIVE_SHORTENER_LURE: {
    en: 'Shortened link hiding destination paired with urgent banking or lottery claims.',
    ta: 'உண்மையான தளத்தை மறைக்கும் சுருக்கப்பட்ட இணைப்புடன் கூடிய அவசர வங்கி எச்சரிக்கை.',
    hi: 'असली पते को छिपाने वाला छोटा लिंक और बैंक या इनाम का झांसा।',
    te: 'అసలు వెబ్‌సైట్‌ను దాచే షార్ట్ లింక్ మరియు బ్యాంక్ లేదా బహుమతి ట్రాప్.'
  },
  SIG_UTILITY_BILL_EXTORTION: {
    en: 'Fake electricity bill disconnection threat scaring citizens into immediate payments.',
    ta: 'இன்றிரவு மின்சாரம் துண்டிக்கப்படும் என மிரட்டி பணம் பறிக்கும் போலி மின்சார கட்டண மோசடி.',
    hi: 'आज रात बिजली कटने की धमकी देकर वसूली करने वाला फर्जी बिल स्कैम।',
    te: 'ఈ రాత్రి కరెంట్ కట్ చేస్తామని బెదిరించి డబ్బులు వసూలు చేసే నకిలీ కరెంట్ బిల్లు మోసం.'
  },
  SIG_FAKE_PARCEL_DELIVERY_LURE: {
    en: 'Fake India Post or courier parcel hold alert soliciting fee or address update.',
    ta: 'தபால் அல்லது பார்சல் டெலிவரி தோல்வி எனக்கூறி ஏமாற்றும் போலி தபால் துறை மோசடி.',
    hi: 'पार्सल डिलीवरी होल्ड का झांसा देकर पता अपडेट या पैसे मांगने वाला फर्जी कूरियर स्कैम।',
    te: 'పార్శిల్ డెలివరీ ఆగిపోయిందని చిరునామా అప్‌డేట్ లేదా డబ్బులు అడిగే నకిలీ కొరియర్ మోసం.'
  },
  SIG_URL_SHORTENER_CAUTION: {
    en: 'Shortened link hides the real destination website. Official agencies rarely use public shorteners.',
    ta: 'சுருக்கப்பட்ட இணைப்பு உண்மையான தளத்தை மறைக்கிறது. அரசு அல்லது வங்கிகள் இதை பயன்படுத்துவதில்லை.',
    hi: 'छोटा लिंक असली वेबसाइट को छुपाता है। बैंक या सरकारी विभाग इसका उपयोग नहीं करते।',
    te: 'షార్ట్ లింక్ అసలు వెబ్‌సైట్‌ను దాస్తుంది. అధికారిక సంస్థలు పబ్లిక్ షార్ట్ లింక్‌లను వాడవు.'
  },
  SIG_NPCI_UNSIGNED_COLLECT_FORENSIC: {
    en: 'Deceptive UPI collect request attempting to deduct money instead of sending you money.',
    ta: 'உங்களுக்கு பணம் அனுப்புவதற்குப் பதிலாக உங்கள் கணக்கிலிருந்து பணத்தை கழிக்கும் போலி கட்டணக் கோரிக்கை.',
    hi: 'पैसे देने के बजाय आपके खाते से पैसे काटने वाला फर्जी UPI पेमेंट अनुरोध।',
    te: 'మీకు డబ్బు పంపే బదులు మీ ఖాతా నుండి డబ్బులు కట్ చేసే నకిలీ UPI చెల్లింపు అభ్యర్థన.'
  },
  SIG_CROSS_ORIGIN_BRAND_ASSET_THEFT: {
    en: 'Fake website stealing official bank logo and icons to disguise an unauthorized login page.',
    ta: 'அங்கீகரிக்கப்படாத உள்நுழைவுப் பக்கத்தை மறைக்க அதிகாரப்பூர்வ வங்கி லோகோ மற்றும் ஐகான்களைத் திருடும் போலி தளம்.',
    hi: 'अनधिकृत लॉगिन पेज को छिपाने के लिए असली बैंक का लोगो और आइकन चुराने वाली फर्जी वेबसाइट।',
    te: 'నకిలీ లాగిన్ పేజీని కప్పిపుచ్చడానికి బ్యాంక్ అసలు లోగో మరియు చిహ్నాలను దొంగిలించిన వెబ్‌సైట్.'
  },
  SIG_REALTIME_KEYLOGGER_HONEYTOKEN_TRIPPED: {
    en: 'Real-time keylogger detected trying to steal card or PIN digits before submission; safely deflected.',
    ta: 'படிவத்தை சமர்ப்பிக்கும் முன்பே கார்டு அல்லது பின் எண்களைத் திருட முயன்ற கீலாக்கர் தடுக்கப்பட்டது.',
    hi: 'सबमिट करने से पहले ही कार्ड या पिन चुराने वाला कीलॉगर पकड़ा गया और सुरक्षित रूप से रोका गया।',
    te: 'సమర్పించడానికి ముందే కార్డు లేదా పిన్ నంబర్లను దొంగిలించడానికి ప్రయత్నించిన కీలాగర్ నిరోధించబడింది.'
  },
  SIG_SURVEILLANCE_EXTORTION_TRAP: {
    en: 'Fake video courtroom or police call demanding webcam or location access to extort money.',
    ta: 'பணம் பறிக்க வெப்கேம் அல்லது இருப்பிட அணுகலைக் கோரும் போலி வீடியோ நீதிமன்றம் அல்லது போலீஸ் அழைப்பு.',
    hi: 'पैसे ऐंठने के लिए वेबकैम या लोकेशन एक्सेस मांगने वाली फर्जी वीडियो कोर्ट या पुलिस कॉल।',
    te: 'డబ్బులు వసూలు చేయడానికి వెబ్‌క్యామ్ లేదా లొకేషన్ యాక్సెస్ అడిగే నకిలీ వీడియో కోర్టు లేదా పోలీసు కాల్.'
  },
  SIG_MALVERTISING_REDIRECT_CHAIN: {
    en: 'Aggressive multi-hop redirect chain rapidly traversing multiple untrusted ad rotators.',
    ta: 'பல நம்பகமற்ற விளம்பர தளங்கள் வழியாக அதிவேகமாக செல்லும் தீங்கிழைக்கும் வழிமாற்று சங்கிலி.',
    hi: 'अनेक अविश्वसनीय विज्ञापन रोटेटर से होकर तेजी से गुजरने वाली खतरनाक री-डायरेक्ट चेन।',
    te: 'అనేక నమ్మదగని ప్రకటన రొటేటర్ల ద్వారా వేగంగా మళ్ళించే ప్రమాదకరమైన దారిమళ్లింపు శృంఖల.'
  },
  SIG_TAB_UNDER_HIJACK: {
    en: 'Tab-under hijack detected: Background tab silently swapped destination domain after popup.',
    ta: 'பின்புல தாவல் கடத்தல்: புதிய சாளரம் திறந்தவுடன் பின்னணி தளம் அமைதியாக மாற்றப்பட்டது.',
    hi: 'टैब-அंडर हाइजैक: पॉपअप खुलने के बाद बैकग्राउंड टैब चुपके से दूसरे डोमेन पर बदल दिया गया।',
    te: 'ట్యాబ్-అండర్ హైజాక్: పాపప్ వచ్చిన తర్వాత బ్యాక్‌గ్రౌండ్ ట్యాబ్ నిశ్శబ్దంగా వేరే డొమైన్‌కు మార్చబడింది.'
  },
  SIG_ARCHIVE_PASSWORD_STEALER_LURE: {
    en: 'Password-protected archive trap: Password displayed in text to evade antivirus inspection of bundled stealer malware.',
    ta: 'கடவுச்சொல் பாதுகாக்கப்பட்ட கோப்பு பொறி: வைரஸ் எதிர்ப்பு சோதனையை ஏமாற்றி மால்வேர் பரப்ப கடவுச்சொல் பக்கத்தில் காட்டப்படுகிறது.',
    hi: 'पासवर्ड-संरक्षित आर्काइव जाल: एंटीवायरस से मैलवेयर छिपाने के लिए पेज पर ही पासवर्ड प्रदर्शित किया गया है।',
    te: 'పాస్‌వర్డ్-రక్షిత ఆర్కైవ్ ట్రాప్: యాంటీవైరస్ స్కానింగ్‌ను తప్పించి మాల్వేర్‌ను దాచడానికి పేజీలోనే పాస్‌వర్డ్ చూపబడింది.'
  },
  SIG_CLICKJACK_INVISIBLE_OVERLAY: {
    en: 'Invisible full-screen clickjack overlay detected to hijack clicks into spawning ad rotators.',
    ta: 'பயனரின் கிளிக்குகளை கடத்தி விளம்பரங்களை திறக்க வடிவமைக்கப்பட்ட கண்ணுக்கு தெரியாத முழுத்திரை மேலடுக்கு.',
    hi: 'क्लिक हाइजैक करने और अनचाहे विज्ञापन खोलने के लिए बनाया गया अदृश्य फुल-स्क्रीन ओवरले।',
    te: 'క్లిక్‌లను హైజాక్ చేసి అవాంఛిత ప్రకటనలను తెరవడానికి రూపొందించిన కనిపించని పూర్తి-స్క్రీన్ ఓవర్‌లే.'
  },
  SIG_FAKE_DOWNLOAD_BUTTON_TRAP: {
    en: 'Fake download button trap: Button routes to an external ad-rotator domain or suspicious executable payload.',
    ta: 'போலி பதிவிறக்க பொத்தான் பொறி: வெளிநாட்டு விளம்பர தளம் அல்லது ஆபத்தான கோப்பிற்கு வழிநடத்துகிறது.',
    hi: 'फर्जी डाउनलोड बटन जाल: बटन बाहरी विज्ञापन रोटेटर या संदिग्ध निष्पादन योग्य फ़ाइल पर ले जाता है।',
    te: 'నకిలీ డౌన్‌లోడ్ బటన్ ట్రాప్: బటన్ బాహ్య యాడ్-రొటేటర్ లేదా అనుమానాస్పద ఫైల్‌కు దారి తీస్తుంది.'
  },
  SIG_NOTIFICATION_PERMISSION_TRAP: {
    en: 'Deceptive notification gate: Coercing notification permissions under the guise of download verification.',
    ta: 'ஏமாற்று அறிவிப்பு பொறி: பதிவிறக்க சரிபார்ப்பு என்ற பெயரில் உலாவி அறிவிப்பு அனுமதியை கட்டாயப்படுத்துகிறது.',
    hi: 'भ्रामक नोटिफिकेशन जाल: डाउनलोड सत्यापन के बहाने ब्राउज़र नोटिफिकेशन अनुमति मांगना।',
    te: 'మోసపూరిత నోటిఫికేషన్ ట్రాప్: డౌన్‌లోడ్ వెరిఫికేషన్ పేరుతో బ్రౌజర్ నోటిఫికేషన్ అనుమతిని బలవంతం చేయడం.'
  },
  SIG_FILE_MAGIC_BYTE_SPOOF: {
    en: 'Disguised dangerous executable: File header reveals program binary masquerading as document.',
    ta: 'ஆவண வடிவில் வேடமிட்ட ஆபத்தான இயக்கக்கூடிய கோப்பு கண்டறியப்பட்டது.',
    hi: 'दस्तावेज़ के रूप में छिपाई गई खतरनाक निष्पादन योग्य फ़ाइल पकड़ी गई।',
    te: 'డాక్యుమెంట్ రూపంలో దాచిన ప్రమాదకరమైన ఎగ్జిక్యూటబుల్ ఫైల్ కనుగొనబడింది.'
  },
  SIG_ARCHIVE_DISGUISED_AS_DOC: {
    en: 'Disguised archive payload: Header reveals ZIP or APK dropper masquerading as standard document.',
    ta: 'ஆவண வடிவில் வேடமிட்ட ஆபத்தான ZIP அல்லது APK செயலி கண்டறியப்பட்டது.',
    hi: 'दस्तावेज़ के रूप में छिपाई गई संदिग्ध ZIP या APK फ़ाइल पकड़ी गई।',
    te: 'డాక్యుమెంట్ రూపంలో దాచిన అనుమానాస్పద ZIP లేదా APK ఫైల్ కనుగొనబడింది.'
  },
  SIG_UNIVERSAL_DOM_CLONE_PHISH: {
    en: 'Cloned phishing template detected: Fake site with dead navigation links attempting to harvest credentials.',
    ta: 'குளோன் செய்யப்பட்ட போலி தளம்: செயலற்ற இணைப்புகளுடன் கடவுச்சொல்லை திருட முயல்கிறது.',
    hi: 'क्लोन की गई फर्जी वेबसाइट: निष्क्रिय लिंक और पासवर्ड चुराने वाला फॉर्म पकड़ा गया।',
    te: 'క్లోన్ చేయబడిన నకిలీ వెబ్‌సైట్: పనిచేయని లింక్‌లతో పాస్‌వర్డ్ దొంగిలించే యత్నం గుర్తించబడింది.'
  },
  SIG_UNIVERSAL_NRD_CREDENTIAL_TRAP: {
    en: 'Zero-day credential trap: Domain registered less than 14 days ago requesting sensitive login credentials.',
    ta: '14 நாட்களுக்குள் புதிதாக பதிவுசெய்யப்பட்ட சந்தேகத்திற்கிடமான தளம் கடவுச்சொற்களை கேட்கிறது.',
    hi: '14 दिन से भी कम पुराना नया डोमेन संवेदनशील लॉगिन विवरण मांग रहा है।',
    te: '14 రోజుల లోపు కొత్తగా నమోదైన అనుమానాస్పద డొమైన్ లాగిన్ వివరాలు అడుగుతోంది.'
  },
  SIG_NEWLY_REGISTERED_DOMAIN_CAUTION: {
    en: 'Newly registered domain: Registered less than 14 days ago. Exercise caution before trusting.',
    ta: 'புதிதாக பதிவு செய்யப்பட்ட தளம்: 14 நாட்களுக்குள் தொடங்கப்பட்டது. கவனமாக இருங்கள்.',
    hi: 'नया पंजीकृत डोमेन: यह वेबसाइट 14 दिन से कम पुरानी है। सतर्क रहें।',
    te: 'ఇటీవలే నమోదైన డొమైన్: ఈ వెబ్‌సైట్ 14 రోజుల కంటే తక్కువ పాతది. జాగ్రత్తగా ఉండండి.'
  },
  SIG_UNIVERSAL_CLIPBOARD_MISMATCH: {
    en: 'Clipboard hijacking attempt: Highlighted text was secretly replaced with an untrusted script, URL, or address.',
    ta: 'கிளிப்போர்டு கடத்தல் முயற்சி: நகலெடுக்கப்பட்ட உரைக்கு பதிலாக தீங்கிழைக்கும் கட்டளை மாற்றப்பட்டது.',
    hi: 'क्लिपबोर्ड हाइजैक प्रयास: कॉपी किए गए टेक्स्ट को चुपके से खतरनाक कमांड या लिंक से बदल दिया गया।',
    te: 'క్లిప్‌బోర్డ్ హైజాక్ యత్నం: కాపీ చేసిన టెక్స్ట్ స్థానంలో ప్రమాదకరమైన ఆదేశం లేదా లింక్ ఉంచబడింది.'
  },
  SIG_CROSS_ORIGIN_PASSWORD_REUSE_TRAP: {
    en: 'Origin password protection: Password used on a different official website was detected on this untrusted origin.',
    ta: 'கடவுச்சொல் பாதுகாப்பு எச்சரிக்கை: வேறொரு தளத்திற்குரிய கடவுச்சொல் இந்த நம்பகமற்ற தளத்தில் பயன்படுத்தப்படுகிறது.',
    hi: 'पासवर्ड सुरक्षा चेतावनी: किसी अन्य वेबसाइट का पासवर्ड इस अविश्वसनीय साइट पर दर्ज किया जा रहा है।',
    te: 'పాస్‌వర్డ్ భద్రతా హెచ్చరిక: వేరే వెబ్‌సైట్ పాస్‌వర్డ్ ఈ నమ్మదగని సైట్‌లో నమోదు చేయబడుతోంది.'
  },
  SIG_CT_LOG_EPHEMERAL_CERT_PHISH: {
    en: 'Ephemeral SSL certificate: Newly issued security certificate detected on an unverified site requesting credentials.',
    ta: 'குறுகிய கால SSL சான்றிதழ்: கடவுச்சொல் கேட்கும் தளத்தில் புதிதாக வழங்கப்பட்ட சான்றிதழ் கண்டறியப்பட்டது.',
    hi: 'अस्थायी SSL प्रमाणपत्र: संवेदनशील विवरण मांगने वाली वेबसाइट पर हाल ही में जारी किया गया प्रमाणपत्र पकड़ा गया।',
    te: 'తాత్కాలిక SSL సర్టిఫికేట్: లాగిన్ వివరాలు అడుగుతున్న సైట్‌లో ఇటీవల జారీ చేయబడిన సర్టిఫికేట్ కనుగొనబడింది.'
  },
  SIG_DNS_CNAME_CLOAKING_DETECTED: {
    en: 'Hidden infrastructure cloak: Website uses deceptive DNS CNAME routing to disguise its true hosting servers.',
    ta: 'மறைக்கப்பட்ட உள்கட்டமைப்பு: உண்மையான சேவையகத்தை மறைக்க DNS CNAME திசைதிருப்பல் பயன்படுத்தப்படுகிறது.',
    hi: 'छिपा हुआ इन्फ्रास्ट्रक्चर: असली सर्वर को छिपाने के लिए यह डोमेन DNS CNAME रूटिंग का उपयोग कर रहा है।',
    te: 'దాచిన ఇన్‌ఫ్రాస్ట్రక్చర్: నిజమైన హోస్టింగ్ సర్వర్‌ను దాచడానికి DNS CNAME రూటింగ్ ఉపయోగించబడుతోంది.'
  },
  SIG_NEURAL_META_FUSION_PHISH: {
    en: 'Multi-layer neural threat: Deep learning fusion engine detected subtle zero-day phishing characteristics.',
    ta: 'நியூரல் அச்சுறுத்தல் பகுப்பாய்வு: ஆழமான நரம்பியல் வலைப்பின்னல் மறைமுக ஃபிஷிங் மோசடியை கண்டறிந்துள்ளது.',
    hi: 'न्यूरल एआई थ्रेट डिटेक्शन: डीप लर्निंग मॉडल ने सूक्ष्म ज़ीरो-डे फ़िशिंग लक्षणों को पकड़ा।',
    te: 'న్యూరల్ AI ముప్పు గుర్తింపు: డీప్ లెర్నింగ్ మోడల్ సూక్ష్మ జీరో-డే ఫిషింగ్ లక్షణాలను గుర్తించింది.'
  },
  SIG_AI_NLP_SCAM_INTENT: {
    en: 'Statistical NLP scam intent: Subword character language model detected fraudulent social engineering or extortion.',
    ta: 'AI மொழி மாதிரியின் எச்சரிக்கை: இந்த செய்தியில் மோசடி அல்லது பணப்பறிப்பு நோக்கம் கண்டறியப்பட்டது.',
    hi: 'AI भाषा मॉडल चेतावनी: इस संदेश में जबरन वसूली या धोखाधड़ी की मंशा पकड़ी गई है।',
    te: 'AI భాషా మోడల్ హెచ్చరిక: ఈ సందేశంలో మోసం లేదా దోపిడీ ఉద్దేశం గుర్తించబడింది.'
  },
  SIG_COMPROMISED_CMS_HOST_PHISH: {
    en: 'Compromised CMS host: Phishing login kit or PHP mailer discovered inside a hacked website directory.',
    ta: 'ஊடுருவப்பட்ட இணையதளம்: ஹேக் செய்யப்பட்ட வலைத்தளக் கோப்புறையில் ஃபிஷிங் உள்நுழைவு அல்லது மின்னஞ்சல் ஸ்கிரிப்ட் கண்டறியப்பட்டது.',
    hi: 'हैक की गई वेबसाइट: हैक की गई CMS डायरेक्टरी में फ़िशिंग लॉगिन किट या PHP मेलर स्क्रिप्ट पकड़ी गई।',
    te: 'హ్యాక్ చేయబడిన వెబ్‌సైట్: హ్యాక్ చేసిన డైరెక్టరీలో ఫిషింగ్ లాగిన్ కిట్ లేదా PHP స్క్రిప్ట్ కనుగొనబడింది.'
  },
  SIG_SERP_SPONSORED_IMPERSONATION: {
    en: 'Search engine ad impersonation: Sponsored ad claims to be an official brand or helpline but points to an untrusted domain.',
    ta: 'தேடுபொறி விளம்பர ஆள்மாறாட்டம்: அதிகாரப்பூர்வ பிராண்ட் அல்லது உதவி எண் எனக்கூறி போலி தளத்திற்கு வழிநடத்தும் விளம்பரம்.',
    hi: 'सर्च इंजन विज्ञापन प्रतिरूपण: आधिकारिक ब्रांड या हेल्पलाइन होने का दावा करने वाला विज्ञापन फर्जी डोमेन पर ले जा रहा है।',
    te: 'సెర్చ్ ఇంజిన్ ప్రకటన మోసం: అధికారిక బ్రాండ్ లేదా హెల్ప్‌లైన్ అని చెప్పి నకిలీ వెబ్‌సైట్‌కు దారితీసే స్పాన్సర్డ్ యాడ్.'
  },
  SIG_APK_TROJAN_BYTECODE_DETECTED: {
    en: 'Malicious APK trojan: Bytecode decompiler uncovered SMS interception, accessibility abuse, or hidden C2 channels.',
    ta: 'தீங்கிழைக்கும் APK ட்ரோஜன்: SMS திருட்டு, அணுகல் கட்டுப்பாடு துஷ்பிரயோகம் அல்லது மறைக்கப்பட்ட கட்டுப்பாட்டு சேவையகம் கண்டறியப்பட்டது.',
    hi: 'दुर्भावनापूर्ण APK ट्रोजन: बाइटकोड विश्लेषण में SMS चोरी, एक्सेसिबिलिटी नियंत्रण और छिपा हुआ C2 सर्वर पकड़ा गया।',
    te: 'ప్రమాదకరమైన APK ట్రోజన్: బైట్‌కోడ్ విశ్లేషణలో SMS చౌర్యం, యాక్సెసిబిలిటీ దుర్వినియోగం మరియు దాచిన C2 సర్వర్ గుర్తించబడింది.'
  },
  SIG_LIVE_CALL_REMOTE_ACCESS_TRAP: {
    en: 'Live call remote access trap: Caller is instructing you to install remote control apps (AnyDesk/TeamViewer) or share your screen.',
    ta: 'நேரடி அழைப்பு தொலைநிலை அணுகல் பொறி: தொலைநிலைக் கட்டுப்பாட்டு செயலிகளை நிறுவ அல்லது திரையைப் பகிர அழைப்பாளர் வழிகாட்டுகிறார்.',
    hi: 'लाइव कॉल रिमोट एक्सेस जाल: कॉलर आपसे रिमोट कंट्रोल ऐप (AnyDesk आदि) इंस्टॉल करने या स्क्रीन शेयर करने को कह रहा है।',
    te: 'లైవ్ కాల్ రిమోట్ యాక్సెస్ ఉచ్చు: కాలర్ మిమ్మల్ని రిమోట్ కంట్రోల్ యాప్‌లను ఇన్‌స్టాల్ చేయమని లేదా స్క్రీన్ షేర్ చేయమని అడుగుతున్నారు.'
  },
  SIG_LIVE_CALL_DIGITAL_ARREST: {
    en: 'Live call digital arrest: Caller posing as police, CBI, or customs officer threatening arrest to extort money.',
    ta: 'நேரடி அழைப்பு டிஜிட்டல் கைது: போலீஸ் அல்லது CBI என நடித்து மிரட்டிப் பணம் பறிக்கும் போலி அதிகாரி அழைப்பு.',
    hi: 'लाइव कॉल डिजिटल अरेस्ट: पुलिस या CBI अधिकारी बनकर गिरफ्तारी की धमकी और जबरन वसूली का कॉल।',
    te: 'లైవ్ కాల్ డిజిటల్ అరెస్ట్: పోలీసులు లేదా CBI అధికారిగా నటించి అరెస్ట్ బెదిరింపుతో డబ్బు వసూలు చేసే మోసపు కాల్.'
  },
  SIG_LIVE_CALL_OTP_HARVEST: {
    en: 'Live call credential harvesting: Caller is attempting to extract your confidential OTP, bank PIN, or QR payment.',
    ta: 'நேரடி அழைப்பு ரகசிய தகவல் திருட்டு: அழைப்பாளர் உங்கள் OTP, வங்கி பின் அல்லது QR குறியீட்டைப் பெற முயற்சிக்கிறார்.',
    hi: 'लाइव कॉल क्रेडेंशियल चोरी: कॉलर आपका गोपनीय OTP, बैंक पिन या QR पेमेंट विवरण निकालने की कोशिश कर रहा है।',
    te: 'లైవ్ కాల్ సమాచార చౌర్యం: కాలర్ మీ రహస్య OTP, బ్యాంక్ పిన్ లేదా QR చెల్లింపు వివరాలను సేకరించడానికి ప్రయత్నిస్తున్నారు.'
  }
};

/**
 * Returns the relevant golden safety rule key for a given threat signal.
 * @param {string} signalId
 * @returns {'upi' | 'digital_arrest' | 'apk' | 'otp_password' | 'generic'}
 */
export function goldenRuleForSignal(signalId) {
  if (!signalId) return 'generic';
  const id = String(signalId.id || signalId).toUpperCase();
  if (id.includes('ARREST') || id.includes('POLICE') || id.includes('CBI') || id.includes('SURVEILLANCE') || id.includes('EXTORTION') || id.includes('SECV') || id.includes('PSYCHOLINGUISTIC')) {
    return 'digital_arrest';
  }
  if (id.includes('APK') || id.includes('MAGIC') || id.includes('ARCHIVE') || id.includes('DOWNLOAD') || id.includes('REMOTE')) {
    return 'apk';
  }
  if (id.includes('UTILITY') || id.includes('ELECTRICITY') || id.includes('PIN') || id.includes('UPI') || id.includes('QR') || id.includes('PAYMENT') || id.includes('COLLECT')) {
    return 'upi';
  }
  if (
    id.includes('CREDENTIAL') ||
    id.includes('PASSWORD') ||
    id.includes('OTP') ||
    id.includes('AITM') ||
    id.includes('WEBHOOK') ||
    id.includes('EXFIL') ||
    id.includes('KYC') ||
    id.includes('PARCEL') ||
    id.includes('SHORTENER') ||
    id.includes('BRAND') ||
    id.includes('KEYLOGGER') ||
    id.includes('HONEYTOKEN') ||
    id.includes('CLONE') ||
    id.includes('PHISH') ||
    id.includes('CLIPBOARD') ||
    id.includes('DOMAIN') ||
    id.includes('REGISTERED') ||
    id.includes('CERT') ||
    id.includes('CLOAK') ||
    id.includes('NEURAL') ||
    id.includes('NLP') ||
    id.includes('CMS') ||
    id.includes('SERP') ||
    id.includes('DMARC') ||
    id.includes('HARVEST')
  ) {
    return 'otp_password';
  }
  return 'generic';
}

/**
 * Retrieves a nested string with automatic fallback to English ('en').
 * Supports dot-notated paths such as 'STATUS.safe', 'UI.checkButton', 'GOLDEN_RULES.upi',
 * or 'REASON_PLAIN.SIG_DIGITAL_ARREST_EXTORTION'.
 *
 * @param {string} lang - 'en' | 'ta' | 'hi' | 'te'
 * @param {string} path - dot-notated key path
 * @returns {string}
 */
export function getText(lang, path) {
  const targetLang = (lang && ['en', 'ta', 'hi', 'te'].includes(lang)) ? lang : 'en';

  const resolve = (l, p) => {
    if (!p) return '';
    const parts = p.split('.');
    if (parts.length === 0) return '';

    const rootKey = parts[0];
    if (rootKey === 'STATUS' && parts.length === 2) {
      return STATUS[l]?.[parts[1]] || '';
    }
    if (rootKey === 'UI' && parts.length === 2) {
      return UI[l]?.[parts[1]] || '';
    }
    if (rootKey === 'GOLDEN_RULES' && parts.length === 2) {
      return GOLDEN_RULES[parts[1]]?.[l] || '';
    }
    if ((rootKey === 'REASON_PLAIN' || rootKey === 'ADVISORIES') && parts.length === 2) {
      return REASON_PLAIN[parts[1]]?.[l] || '';
    }
    return '';
  };

  const text = resolve(targetLang, path);
  if (text) return text;
  if (targetLang !== 'en') {
    return resolve('en', path);
  }
  return '';
}

/**
 * Detects the user's preferred language from navigator.language.
 * @param {string} [navigatorLanguage]
 * @returns {'ta' | 'hi' | 'te' | 'en'}
 */
export function detectDefaultLang(navigatorLanguage) {
  if (!navigatorLanguage || typeof navigatorLanguage !== 'string') return 'en';
  const lower = navigatorLanguage.toLowerCase().trim();
  if (lower.startsWith('ta')) return 'ta';
  if (lower.startsWith('hi')) return 'hi';
  if (lower.startsWith('te')) return 'te';
  return 'en';
}

export const ADVISORIES = REASON_PLAIN;

export default {
  LANGS,
  STATUS,
  UI,
  GOLDEN_RULES,
  REASON_PLAIN,
  ADVISORIES,
  goldenRuleForSignal,
  getText,
  detectDefaultLang
};
