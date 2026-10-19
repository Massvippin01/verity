/**
 * top_domains.js — Curated Global Top Established Domains (Tranco / Alexa Top Sites)
 *
 * Provides reputation shielding for major, verified global websites to prevent
 * heuristic false positives on legitimate brands, media, travel, and SaaS tools.
 */

export const TOP_GLOBAL_DOMAINS = new Set([
  // Top Search, Portals & Identity
  'google.com', 'google.co.uk', 'google.co.in', 'google.de', 'google.fr', 'google.co.jp', 'google.ca', 'google.com.au',
  'youtube.com', 'youtube-nocookie.com', 'youtu.be', 'yahoo.com', 'bing.com', 'duckduckgo.com', 'baidu.com', 'yandex.ru',
  'msn.com', 'live.com', 'microsoft.com', 'office.com', 'apple.com', 'icloud.com',

  // Social & Communication
  'facebook.com', 'meta.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 'reddit.com',
  'pinterest.com', 'tumblr.com', 'tiktok.com', 'snapchat.com', 'whatsapp.com', 'telegram.org',
  'discord.com', 'discord.gg', 'slack.com', 'zoom.us', 'zoom.com', 'skype.com',

  // Developer, Cloud & SaaS
  'github.com', 'github.io', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com', 'stackexchange.com',
  'npmjs.com', 'pypi.org', 'cloudflare.com', 'digitalocean.com', 'heroku.com', 'vercel.com',
  'netlify.com', 'docker.com', 'postman.com', 'atlassian.com', 'atlassian.net', 'jira.com', 'trello.com',
  'notion.so', 'notion.site', 'figma.com', 'canva.com', 'miro.com', 'airtable.com',
  'salesforce.com', 'hubspot.com', 'zendesk.com', 'intercom.com', 'stripe.com', 'shopify.com',
  'wix.com', 'squarespace.com', 'godaddy.com', 'namecheap.com', 'fastly.com',

  // Media, Publishing & Journalism
  'fox.com', 'foxnews.com', 'vox.com', 'theverge.com', 'polygon.com', 'eater.com',
  'nytimes.com', 'cnn.com', 'bbc.com', 'bbc.co.uk', 'theguardian.com', 'bloomberg.com',
  'forbes.com', 'reuters.com', 'wsj.com', 'washingtonpost.com', 'latimes.com', 'usatoday.com',
  'time.com', 'economist.com', 'nationalgeographic.com', 'wired.com', 'techcrunch.com',
  'arstechnica.com', 'engadget.com', 'cnet.com', 'zdnet.com', 'ign.com', 'gamespot.com',
  'medium.com', 'substack.com', 'quora.com',

  // Streaming & Entertainment
  'netflix.com', 'spotify.com', 'vimeo.com', 'twitch.tv', 'soundcloud.com', 'dailymotion.com',
  'hulu.com', 'disneyplus.com', 'max.com', 'hbomax.com', 'paramountplus.com', 'crunchyroll.com',
  'imdb.com', 'rottentomatoes.com', 'steamcommunity.com', 'steampowered.com',

  // Travel, Real Estate & Modern Services
  'trip.com', 'tripadvisor.com', 'booking.com', 'airbnb.com', 'expedia.com', 'kayak.com',
  'hotels.com', 'agoda.com', 'skyscanner.net', 'uber.com', 'lyft.com', 'doordash.com',
  'zillow.com', 'redfin.com', 'realtor.com', 'craigslist.org', 'yelp.com',
  'loom.com', 'viva.com', 'lulu.com', 'box.com', 'dropbox.com',

  // E-Commerce & Retail
  'amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.fr', 'amazon.co.jp',
  'ebay.com', 'ebay.co.uk', 'etsy.com', 'walmart.com', 'target.com', 'bestbuy.com',
  'costco.com', 'homedepot.com', 'lowes.com', 'ikea.com', 'wayfair.com', 'aliexpress.com',
  'alibaba.com', 'flipkart.com',

  // Reference, Health & Education
  'wikipedia.org', 'wikimedia.org', 'w3schools.com', 'archive.org', 'coursera.org',
  'udemy.com', 'khanacademy.org', 'edx.org', 'duolingo.com', 'quizlet.com',
  'britannica.com', 'merriam-webster.com', 'dictionary.com', 'investopedia.com',
  'healthline.com', 'webmd.com', 'mayoclinic.org', 'nih.gov', 'cdc.gov', 'who.int', 'nasa.gov'
]);

export default TOP_GLOBAL_DOMAINS;
