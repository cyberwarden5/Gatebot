import re
import asyncio
from pyrogram import Client, filters
from pyrogram.types import Message
import aiohttp
import os
import warnings
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
import json
from googlesearch import search
import urllib.parse

# Suppress SSL verification warnings
warnings.simplefilter('ignore', InsecureRequestWarning)

# Bot configuration
API_ID = 23883349
API_HASH = "9ae2939989ed439ab91419d66b61a4a4"
BOT_TOKEN = "7842856490:AAGK3IHkatwgNAliRjF1orLCyohjLEUVK9g"
ADMIN_ID = 5429071679

# Initialize the bot
app = Client("gateway_checker_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# Enhanced gateway detection patterns
GATEWAYS = {
    "Stripe": [
        r"<script[^>]*src=['\"]https?://js\.stripe\.com/v\d/['\"]",
        r"<script[^>]*src=['\"]https?://r\.stripe\.com/b['\"]",
        r"stripe\.com/v\d/tokens",
        r"stripe\.com/v\d/payment_intents",
        r"checkout\.stripe\.com",
        r"stripe\.com/v\d/elements",
        r"Stripe$$(['\"](pk_live|pk_test)_[0-9a-zA-Z]+['\"]$$",
        r"stripe\.createToken",
        r"stripe\.confirmCardPayment",
        r"stripe\.handleCardPayment",
        r"stripe\.createPaymentMethod",
        r"stripe\.elements$$$$",
        r"data-stripe=['\"][^'\"]+['\"]",
        r"id=['\"]card-element['\"]",
        r"stripeTokenHandler",
        r"stripe-button",
        r"stripe-payment",
        r"stripeBilling"
    ],
    "Braintree": [
        r"<script[^>]*src=['\"]https?://js\.braintreegateway\.com/[^'\"]+['\"]",
        r"<script[^>]*src=['\"]https?://api\.braintreegateway\.com/[^'\"]+['\"]",
        r"client_token_url",
        r"braintree_client_token",
        r"braintree/client_token",
        r"braintree\.setup",
        r"braintree\.client\.create",
        r"braintree\.paypal\.create",
        r"braintree\.hostedFields\.create",
        r"braintree\.dropin\.create",
        r"data-braintree-name",
        r"braintree-payment-form",
        r"bt-card-number",
        r"bt-expiration",
        r"bt-cvv",
        r"braintree\.env\.sandbox",
        r"braintree\.env\.production",
        r"braintree-hosted-fields-invalid",
        r"braintree-hosted-fields-valid"
    ],
    "PayPal": [
        r"paypal\.com/sdk/js",
        r"<script[^>]*src=['\"]https?://www\.paypalobjects\.com/[^'\"]+['\"]",
        r"paypal\.Buttons",
        r"paypal-button",
        r"paypal-payment",
        r"paypal\.com/v1/",
        r"paypal\.com/v2/checkout",
        r"paypal\.com/smart/buttons",
        r"data-paypal-button",
        r"paypal\.FUNDING\.",
        r"paypal-sdk",
        r"paypal-instance",
        r"paypal\.Orders\.create"
    ],
    "Square": [
        r"squareup\.com/payments",
        r"square\.com/js/sq-payment-form",
        r"SqPaymentForm",
        r"square-payment-form",
        r"SquarePaymentFlow",
        r"square\.com/v1/payments",
        r"square\.com/v2/payments",
        r"data-square",
        r"square-button"
    ],
    "Amazon Pay": [
        r"payments\.amazon\.",
        r"payments-amazon\.",
        r"amazonpayments\.",
        r"amazon\.Pay\.renderButton",
        r"amazon\.Pay\.initCheckout",
        r"OffAmazonPayments",
        r"amazon-pay-button",
        r"amazonpay-button"
    ],
    "Klarna": [
        r"klarna\.com",
        r"klarna-payments",
        r"klarna-checkout",
        r"klarna\.load",
        r"KlarnaPayments",
        r"klarna_payments",
        r"klarna-payment-method",
        r"_klarnaCheckout"
    ],
    "Adyen": [
        r"adyen\.com",
        r"checkoutshopper-live\.adyen\.com",
        r"checkoutshopper-test\.adyen\.com",
        r"adyen\.checkout",
        r"AdyenCheckout",
        r"adyen-checkout",
        r"adyen-encrypted-data",
        r"data-adyen"
    ],
    "Authorize.net": [
        r"accept\.authorize\.net",
        r"acceptjs\.authorize\.net",
        r"AcceptUI",
        r"accept\.js",
        r"authorizenet",
        r"authorize-net",
        r"AuthorizeNetSeal",
        r"AuthorizeNetPopup"
    ],
    "Worldpay": [
        r"worldpay\.com",
        r"worldpay\.js",
        r"worldpay-js",
        r"WorldpayHOP",
        r"worldpay\.setup",
        r"data-worldpay",
        r"worldpay-payment"
    ],
    "Cybersource": [
        r"cybersource\.com",
        r"cybersource\.min\.js",
        r"cybersource/checkout",
        r"cybs",
        r"cybersource-flex",
        r"cybersource-token",
        r"data-cybersource"
    ],
    "2Checkout": [
        r"2checkout\.com",
        r"2co\.com",
        r"2checkout\.js",
        r"2co_signature",
        r"twocheckout",
        r"2checkout-form",
        r"2checkout-token"
    ],
    "Eway": [
        r"eway\.com\.au",
        r"eWAY",
        r"eway\.rapidapi"
    ],
    "NMI": [
        r"secure\.networkmerchants\.com",
        r"CollectJS",
        r"collect\.js"
    ],
    "WooCommerce": [
        r"woocommerce",
        r"WC_AJAX",
        r"wc-payment"
    ]
}

# Enhanced captcha detection patterns
CAPTCHA_TYPES = {
    "reCAPTCHA v2": [
        r"www\.google\.com/recaptcha/api\.js",
        r"grecaptcha\.render",
        r"g-recaptcha",
        r"recaptcha-token",
        r"data-sitekey=\"[^\"]*\"",
        r"class=\"g-recaptcha\"",
        r"grecaptcha\.execute"
    ],
    "reCAPTCHA v3": [
        r"grecaptcha\.execute\('[^']+', *{action:",
        r"google\.com/recaptcha/api\.js\?render=",
        r"grecaptcha\.ready",
        r"data-recaptcha-action"
    ],
    "hCaptcha": [
        r"hcaptcha\.com/1/api\.js",
        r"data-hcaptcha",
        r"h-captcha",
        r"hcaptcha-response",
        r"hcaptcha\.render",
        r"hcaptcha-widget"
    ],
    "Arkose Labs": [
        r"arkoselabs\.com",
        r"funcaptcha",
        r"arkoselabs-client",
        r"data-callback=\"arkoseCallback\"",
        r"arkose-enforcement"
    ],
    "Custom Captcha": [
        r"captcha\.php",
        r"custom-captcha",
        r"captcha-form",
        r"captcha-image",
        r"captcha-input",
        r"captcha\.generate",
        r"captcha\.verify"
    ],
    "BotDetect": [
        r"botdetect/",
        r"BotDetect\.init",
        r"BDC_",
        r"botdetect-captcha"
    ],
    "KeyCaptcha": [
        r"keycaptcha\.com",
        r"s_s_c_user_id",
        r"KeyCAPTCHA_"
    ],
    "GeeTest": [
        r"geetest\.com",
        r"gt_captcha",
        r"initGeetest",
        r"geetest_challenge"
    ]
}

# Enhanced security detection patterns
SECURITY_PATTERNS = {
    "WAF": [
        r"cloudflare",
        r"sucuri",
        r"incapsula",
        r"akamai",
        r"imperva",
        r"distil"
    ],
    "Anti-Bot": [
        r"datadome",
        r"perimeterx",
        r"shapeshifter",
        r"__cf_bm",
        r"_px\d?",
        r"botprotection"
    ],
    "Fingerprinting": [
        r"fingerprintjs",
        r"fp\.min\.js",
        r"fingerprint2",
        r"visitorid",
        r"deviceprint"
    ],
    "DDoS Protection": [
        r"ddos-guard",
        r"raygun",
        r"shield-protection",
        r"anti-ddos",
        r"ddos_sensor"
    ]
}

# Platform detection patterns
PLATFORMS = {
    "WordPress": [
        r"wp-content",
        r"wp-includes",
        r"wp-admin",
        r"wp-json",
        r"wordpress",
        r"wp-login",
        r"wp-config"
    ],
    "Shopify": [
        r"myshopify\.com",
        r"shopify\.com",
        r"shopify-section",
        r"shopify\.theme",
        r"shopify-payment-button",
        r"/cdn\.shopify\.com/"
    ],
    "Magento": [
        r"magento",
        r"mage-init",
        r"magento-version",
        r"mage/",
        r"Mage\.",
        r"magento-store"
    ],
    "WooCommerce": [
        r"woocommerce",
        r"wc-api",
        r"wc-ajax",
        r"wc-checkout",
        r"wc-cart",
        r"woocommerce-cart"
    ],
    "PrestaShop": [
        r"prestashop",
        r"presta-shop",
        r"prestashop-admin",
        r"ps_",
        r"prestashop\.com"
    ],
    "OpenCart": [
        r"opencart",
        r"route=common",
        r"route=product",
        r"route=checkout"
    ],
    "Joomla": [
        r"joomla",
        r"option=com_",
        r"mosConfig",
        r"joomla-script",
        r"joomla\.javascript"
    ],
    "Custom PHP": [
        r"\.php",
        r"php-script",
        r"phpinfo",
        r"php-form"
    ],
    "Laravel": [
        r"laravel",
        r"csrf-token",
        r"laravel_session",
        r"laravel\.js"
    ],
    "Django": [
        r"csrfmiddlewaretoken",
        r"django",
        r"staticfiles",
        r"djangojs"
    ]
}

# Store registered users
registered_users = set()

async def analyze_security_features(html, headers, soup):
    """
    Advanced security feature analysis
    """
    security_features = {
        "WAF": [],
        "Anti-Bot": [],
        "Fingerprinting": [],
        "DDoS Protection": [],
        "Headers": {
            "CSP": bool(headers.get("Content-Security-Policy")),
            "HSTS": bool(headers.get("Strict-Transport-Security")),
            "XFO": bool(headers.get("X-Frame-Options")),
            "XXP": bool(headers.get("X-XSS-Protection")),
            "COOP": bool(headers.get("Cross-Origin-Opener-Policy")),
            "CORP": bool(headers.get("Cross-Origin-Resource-Policy"))
        }
    }

    # Check security patterns
    for category, patterns in SECURITY_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                security_features[category].append(pattern)

    # Additional header checks
    security_headers = {
        "Server": headers.get("Server", ""),
        "X-Powered-By": headers.get("X-Powered-By", ""),
        "X-AspNet-Version": headers.get("X-AspNet-Version", ""),
        "X-Runtime": headers.get("X-Runtime", "")
    }

    return security_features, security_headers

async def detect_captcha(html, soup):
    """
    Advanced captcha detection with type identification
    """
    captcha_info = {
        "detected": False,
        "types": [],
        "details": {}
    }

    for captcha_type, patterns in CAPTCHA_TYPES.items():
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                captcha_info["detected"] = True
                if captcha_type not in captcha_info["types"]:
                    captcha_info["types"].append(captcha_type)
                    
                # Get additional details for specific captcha types
                if captcha_type == "reCAPTCHA v2":
                    sitekey = re.search(r'data-sitekey="([^"]*)"', html)
                    if sitekey:
                        captcha_info["details"]["reCAPTCHA_sitekey"] = sitekey.group(1)
                elif captcha_type == "hCaptcha":
                    sitekey = re.search(r'data-sitekey="([^"]*)"', html)
                    if sitekey:
                        captcha_info["details"]["hCaptcha_sitekey"] = sitekey.group(1)

    # Check for invisible captchas
    if re.search(r'invisible-recaptcha|invisible_recaptcha|grecaptcha\.execute', html, re.IGNORECASE):
        captcha_info["details"]["invisible_captcha"] = True

    return captcha_info

async def detect_platform(html, headers, soup):
    async def detect_platform(html, headers, soup):
        """
        Advanced platform detection
        """
        detected_platforms = []
        platform_details = {}

    for platform, patterns in PLATFORMS.items():
        if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
            detected_platforms.append(platform)
            
            # Get additional platform-specific details
            if platform == "WordPress":
                version = re.search(r'meta name="generator" content="WordPress ([^"]*)"', html)
                if version:
                    platform_details["wp_version"] = version.group(1)
            elif platform == "Shopify":
                theme = re.search(r'Shopify\.theme\s*=\s*({[^}]*})', html)
                if theme:
                    platform_details["shopify_theme"] = theme.group(1)

    return detected_platforms, platform_details

async def check_gateway(url):
    """
    Enhanced gateway checking with advanced detection methods
    """
    try:
        async with aiohttp.ClientSession() as session:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Cache-Control': 'max-age=0'
            }

            async with session.get(url, ssl=False, timeout=15, headers=headers) as response:
                html = await response.text()
                status_code = response.status
                resp_headers = response.headers

                soup = BeautifulSoup(html, 'html.parser')

                # Gateway detection
                gateways_found = []
                gateway_details = {}

                for gateway, patterns in GATEWAYS.items():
                    if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                        gateways_found.append(gateway)
                        
                        # Get additional gateway-specific details
                        if gateway == "Stripe":
                            pk = re.search(r'pk_(test|live)_\w+', html)
                            if pk:
                                gateway_details["stripe_pk"] = pk.group(0)
                        elif gateway == "PayPal":
                            client_id = re.search(r'client-id="([^"]*)"', html)
                            if client_id:
                                gateway_details["paypal_client_id"] = client_id.group(1)

                # Security analysis
                security_features, security_headers = await analyze_security_features(html, resp_headers, soup)

                # Captcha detection
                captcha_info = await detect_captcha(html, soup)

                # Platform detection
                platforms, platform_details = await detect_platform(html, resp_headers, soup)

                return {
                    "status_code": status_code,
                    "gateways": {
                        "found": gateways_found,
                        "details": gateway_details
                    },
                    "platform": {
                        "detected": platforms[0] if platforms else "Unknown",
                        "details": platform_details
                    },
                    "captcha": captcha_info,
                    "security": security_features,
                    "headers": security_headers
                }

    except asyncio.TimeoutError:
        return {"error": "🕒 Connection timeout"}
    except aiohttp.ClientError as e:
        return {"error": f"🔌 Connection error: {str(e)}"}
    except Exception as e:
        return {"error": f"❌ Unexpected error: {str(e)}"}

@app.on_message(filters.command("start"))
async def start_command(client, message: Message):
    user_id = message.from_user.id
    if user_id not in registered_users:
        start_text = (
            "🌟 **Welcome to Gateway Checker Bot!** 🌟\n\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🔐 To get started, please register:\n"
            "➜ Use /register command\n\n"
            "📝 After registration, you can:\n"
            "➜ Check URLs with /chk\n"
            "➜ Process bulk URLs with /txt\n"
            "➜ Search URLs with /search\n"
            "➜ Learn more with /about\n"
            "━━━━━━━━━━━━━━━━━━━━\n\n"
            "🛡️ Stay secure and happy checking!"
        )
        await message.reply(start_text, reply_to_message_id=message.id)
    else:
        welcome_back = (
            "🎉 **Welcome back!** 🎉\n\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🔍 Ready to check some gateways?\n\n"
            "📋 **Available Commands:**\n"
            "➜ /chk - Check URLs\n"
            "➜ /txt - Process bulk URLs\n"
            "➜ /search - Search URLs\n"
            "➜ /about - Bot information\n"
            "━━━━━━━━━━━━━━━━━━━━\n\n"
            "💫 Let's get started!"
        )
        await message.reply(welcome_back, reply_to_message_id=message.id)

@app.on_message(filters.command("register"))
async def register_command(client, message: Message):
    user_id = message.from_user.id
    if user_id not in registered_users:
        registered_users.add(user_id)
        user_info = (
            "🆕 **New User Registration**\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 **Name:** {message.from_user.first_name}\n"
            f"🔖 **Username:** @{message.from_user.username}\n"
            f"🆔 **ID:** `{user_id}`\n"
            "━━━━━━━━━━━━━━━━━━━━"
        )
        await client.send_message(ADMIN_ID, user_info)
        
        success_msg = (
            "✅ **Registration Successful!**\n\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🎉 Welcome to Gateway Checker Bot!\n\n"
            "📋 **Available Commands:**\n"
            "➜ /chk - Check URLs\n"
            "➜ /txt - Process bulk URLs\n"
            "➜ /search - Search URLs\n"
            "➜ /about - Bot information\n"
            "━━━━━━━━━━━━━━━━━━━━\n\n"
            "🚀 Ready to start checking!"
        )
        await message.reply(success_msg, reply_to_message_id=message.id)
    else:
        already_reg = (
            "ℹ️ **Already Registered**\n\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "You're already registered and can use all bot features!\n\n"
            "Need help? Use /about for more information.\n"
            "━━━━━━━━━━━━━━━━━━━━"
        )
        await message.reply(already_reg, reply_to_message_id=message.id)

@app.on_message(filters.command("search"))
async def search_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply("🚫 You need to register first. Please use the /register command.", 
                          reply_to_message_id=message.id)
        return

    try:
        # Parse command arguments
        args = message.text.split(None, 2)
        if len(args) < 3:
            await message.reply(
                "❌ **Invalid Format!**\n\n"
                "📝 **Usage:**\n"
                "`/search <query> <amount>`\n\n"
                "📌 **Example:**\n"
                "`/search intext:\"payment\" 10`",
                reply_to_message_id=message.id
            )
            return

        query = args[1]
        try:
            amount = int(args[2])
            if amount > 50:
                amount = 50
        except ValueError:
            amount = 10

        # Send initial status
        status_msg = await message.reply(
            "🔍 **Searching URLs...**\n"
            "Please wait...",
            reply_to_message_id=message.id
        )

        # Perform Google search
        urls = []
        for url in search(query, num_results=amount):
            if "google.com" not in url:
                urls.append(url)

        if not urls:
            await status_msg.edit(
                "❌ **No Results Found!**\n"
                "Try a different search query."
            )
            return

        # Format results
        result_text = (
            f"🔍 **Search Results**\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🔎 **Query:** `{query}`\n"
            f"📊 **Found:** `{len(urls)}` URLs\n"
            f"━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📋 **URLs List:**\n"
        )

        for i, url in enumerate(urls, 1):
            result_text += f"`{i}. {url}`\n"

        result_text += "\n━━━━━━━━━━━━━━━━━━━━"

        await status_msg.edit(result_text)

    except Exception as e:
        await message.reply(
            f"❌ **Error:**\n`{str(e)}`",
            reply_to_message_id=message.id
        )

@app.on_message(filters.command("about"))
async def about_command(client, message: Message):
    about_text = (
        "🔍 **Gateway Checker Bot**\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "🤖 **Bot Features:**\n"
        "➜ Multiple URL checking\n"
        "➜ Bulk processing via text file\n"
        "➜ Advanced gateway detection\n"
        "➜ Security measure analysis\n"
        "➜ URL search functionality\n\n"
        "📋 **Commands:**\n"
        "➜ /chk - Check URLs (up to 15)\n"
        "➜ /txt - Process URLs from file\n"
        "➜ /search - Search for URLs\n\n"
        "💳 **Supported Gateways:**\n"
        "➜ Stripe 💳\n"
        "➜ Braintree 🧠\n"
        "➜ PayPal 💰\n"
        "➜ Square ⬜\n"
        "➜ Amazon Pay 📦\n"
        "➜ Apple Pay 🍎\n"
        "➜ Google Pay 🌐\n"
        "➜ Adyen 💸\n"
        "➜ Authorize.net 🔐\n"
        "➜ 2Checkout 2️⃣\n"
        "➜ Klarna 🛍️\n"
        "➜ Eway 💳\n"
        "➜ NMI 🔢\n"
        "➜ WooCommerce 🛒\n\n"
        "🛡️ **Security Checks:**\n"
        "➜ Cloudflare Protection\n"
        "➜ Captcha Systems\n"
        "➜ Platform Detection\n"
        "➜ Security Headers\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "🚀 Happy checking!"
    )
    await message.reply(about_text, reply_to_message_id=message.id)

@app.on_message(filters.command("chk"))
async def chk_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply("🚫 You need to register first. Please use the /register command.", 
                          reply_to_message_id=message.id)
        return

    # Extract URLs from the message
    if message.reply_to_message:
        text = message.reply_to_message.text or message.reply_to_message.caption
    else:
        text = message.text

    # Use regex to find URLs in the text
    urls = re.findall(r'https?://\S+', text)

    if not urls:
        await message.reply("❌ Please provide URLs to check.", 
                          reply_to_message_id=message.id)
        return

    if len(urls) > 15:
        await message.reply("❌ Maximum 15 URLs allowed.", 
                          reply_to_message_id=message.id)
        return

    response = await message.reply("🔍 **Gateway Checker**\n━━━━━━━━━━━━━━", 
                                 reply_to_message_id=message.id)
    results = []

    for url in urls:
        result = await check_gateway(url)
        if "error" in result:
            gateway_info = (
                f"🔍 **Error Checking Gateway** ❌\n"
                f"━━━━━━━━━━━━━━\n"
                f"➜ **URL:** `{url}`\n"
                f"➜ **Error:** `{result['error']}`\n"
                f"━━━━━━━━━━━━━━\n\n"
            )
        else:
            captcha_info = ""
            if result['captcha']['detected']:
                captcha_info = (
                    f"⚠️ **Captcha Details:**\n"
                    f"➜ Types: {', '.join(result['captcha']['types'])}\n"
                )

            gateway_info = (
                f"🔍 **Gateway Fetched Successfully** ✅\n"
                f"━━━━━━━━━━━━━━\n"
                f"➜ **URL:** `{url}`\n"
                f"➜ **Payment Gateways:** {', '.join(result['gateways']['found']) if result['gateways']['found'] else 'None'}\n"
                f"➜ **Platform:** {result['platform']['detected']}\n"
                f"➜ **Captcha Detected:** {'⚠️ Yes' if result['captcha']['detected'] else 'No'}\n"
                f"{captcha_info if result['captcha']['detected'] else ''}"
                f"➜ **Cloudflare:** {'⚡ Yes' if result['security']['WAF'] else 'No'}\n"
                f"➜ **Security Features:**\n"
                f"   • SSL: {'✅' if result['security']['Headers']['CSP'] else '❌'}\n"
                f"   • CSP: {'✅' if result['security']['Headers']['CSP'] else '❌'}\n"
                f"   • HSTS: {'✅' if result['security']['Headers']['HSTS'] else '❌'}\n"
                f"   • XSS Protection: {'✅' if result['security']['Headers']['XXP'] else '❌'}\n"
                f"➜ **Status Code:** {result['status_code']}\n"
                f"━━━━━━━━━━━━━━\n\n"
            )
        
        results.append(gateway_info)
        
        full_message = "🔍 **Gateway Checker**\n━━━━━━━━━━━━━━\n\n" + "".join(results)
        
        try:
            await response.edit(full_message)
        except Exception as e:
            response = await message.reply(full_message, 
                                        reply_to_message_id=message.id)

@app.on_message(filters.command("txt") & filters.reply)
async def txt_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply("🚫 You need to register first. Please use the /register command.", 
                          reply_to_message_id=message.id)
        return

    replied_message = message.reply_to_message
    if not replied_message.document or not replied_message.document.file_name.endswith('.txt'):
        await message.reply("❌ Please reply to a .txt file containing URLs.", 
                          reply_to_message_id=message.id)
        return

    file = await replied_message.download()
    with open(file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    os.remove(file)

    if not urls:
        await message.reply("❌ No valid URLs found in the file.", 
                          reply_to_message_id=message.id)
        return

    total_urls = len(urls)
    response = await message.reply(
        f"📊 **Mass URL Checker**\n"
        f"━━━━━━━━━━━━━━\n"
        f"➜ Found: {total_urls} URLs\n"
        f"➜ Status: Starting check...\n"
        f"━━━━━━━━━━━━━━", 
        reply_to_message_id=message.id
    )

    results = {gateway: [] for gateway in GATEWAYS.keys()}
    checked = 0
    found_gateways = set()

    async def update_message():
        while checked < total_urls:
            await asyncio.sleep(2)
            remaining = total_urls - checked
            
            status_lines = [
                "🔍 **MASS CHECKER**\n"
                "━━━━━━━━━━━━━━\n"
                f"📊 **Progress:**\n"
                f"➜ Total: {total_urls}\n"
                f"➜ Checked: {checked}\n"
                f"➜ Remaining: {remaining}\n"
                "━━━━━━━━━━━━━━\n"
            ]
            
            if found_gateways:
                status_lines.append("💳 **Found Gateways:**\n")
                for gateway in found_gateways:
                    status_lines.append(f"➜ {gateway}: {len(results[gateway])}\n")
            
            status = "".join(status_lines)
            try:
                await response.edit(status)
            except Exception:
                pass

    update_task = asyncio.create_task(update_message())

    for url in urls:
        result = await check_gateway(url)
        checked += 1
        if "error" not in result and result["gateways"]["found"]:
            for gateway in result["gateways"]["found"]:
                results[gateway].append(url)
                found_gateways.add(gateway)

    update_task.cancel()

    # Send final results
    for gateway, urls in results.items():
        if urls:
            result_text = (
                f"🔍 **{gateway} Hits**\n"
                f"━━━━━━━━━━━━━━\n"
                f"`{'`\n`'.join(urls)}`"
            )
            try:
                await message.reply(result_text, reply_to_message_id=message.id)
            except Exception:
                chunks = [urls[i:i + 50] for i in range(0, len(urls), 50)]
                for i, chunk in enumerate(chunks):
                    chunk_text = (
                        f"🔍 **{gateway} Hits (Part {i+1})**\n"
                        f"━━━━━━━━━━━━━━\n"
                        f"`{'`\n`'.join(chunk)}`"
                    )
                    await message.reply(chunk_text, reply_to_message_id=message.id)

    final_status = (
        "✅ **Check completed!**\n"
        "━━━━━━━━━━━━━━\n"
        f"📊 **Results Summary:**\n"
        f"➜ Total URLs: {total_urls}\n"
    )

    if found_gateways:
        final_status += "\n💳 **Gateway Hits:**\n"
        for gateway in found_gateways:
            final_status += f"➜ {gateway}: {len(results[gateway])}\n"

    final_status += "━━━━━━━━━━━━━━"
    await response.edit(final_status)

# Run the bot
app.run()

