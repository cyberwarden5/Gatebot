import re
import asyncio
from pyrogram import Client, filters
from pyrogram.types import Message
import aiohttp
import os
import warnings
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
from googlesearch import search
import cloudscraper
import shlex

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
        r"stripe\.com/v\d/tokens",
        r"stripe\.com/v\d/payment_intents",
        r"checkout\.stripe\.com",
        r"stripe\.com/v\d/elements",
        r"Stripe\(['\"](?:pk_live|pk_test)_[0-9a-zA-Z]+['\"]",
        r"stripe\.createToken",
        r"stripe\.confirmCardPayment",
        r"stripe\.handleCardPayment",
        r"stripe\.createPaymentMethod",
        r"data-stripe=['\"][^'\"]+['\"]",
        r"id=['\"]card-element['\"]",
    ],
    "Braintree": [
        r"<script[^>]*src=['\"]https?://js\.braintreegateway\.com/[^'\"]+['\"]",
        r"braintree_client_token",
        r"braintree/client_token",
        r"braintree\.setup",
        r"braintree\.client\.create",
        r"braintree\.paypal\.create",
        r"braintree\.hostedFields\.create",
        r"braintree\.dropin\.create",
        r"data-braintree-name",
        r"braintree-payment-form",
        r"graphql\.braintreegateway\.com",
    ],
    "PayPal": [
        r"paypal\.com/sdk/js(?:\?|\&)",
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
        r"squareup\.com/payments(?:[^\w])",
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
        r"amazon\.(payments|pay)\.",
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
        r"accept(?:\.authorize\.net|\.js|\.ui)",
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
        r"worldpay\.setup|worldpay\.js",
        r"data-worldpay",
        r"worldpay-payment"
    ],
    "Cybersource": [
        r"cybersource\.com",
        r"cybersource(?:\.min|\.js)",
        r"cybersource/checkout",
        r"cybs",
        r"cybersource-flex",
        r"cybersource-token",
        r"data-cybersource"
    ],
    "2Checkout": [
        r"2checkout\.(com|js)",
        r"2co\.com",
        r"2checkout\.js",
        r"2co_signature",
        r"twocheckout",
        r"2checkout-form",
        r"2checkout-token"
    ],
    "Eway": [
        r"eway\.(com\.au|com)",
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
        r"wc-(payment|ajax)"
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

# Store registered users
registered_users = set()

async def check_gateway(url):
    """
    Enhanced gateway checking with advanced detection methods using cloudscraper
    """
    try:
        scraper = cloudscraper.create_scraper(
            browser={
                'browser': 'chrome',
                'platform': 'windows',
                'mobile': False
            }
        )
        
        response = await asyncio.to_thread(
            lambda: scraper.get(
                url,
                timeout=15,
                verify=False
            )
        )

        html = response.text
        status_code = response.status_code

        # Gateway detection with enhanced visual indicators
        gateways_found = []
        for gateway, patterns in GATEWAYS.items():
            if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                gateways_found.append(f"✨ {gateway}")

        # Enhanced status indicators
        status_indicators = {
            200: "✅",
            201: "✅",
            301: "↪️",
            302: "↪️",
            400: "⚠️",
            401: "🔒",
            403: "⛔",
            404: "❌",
            500: "💥",
            503: "⚡"
        }
        status_icon = status_indicators.get(status_code, "ℹ️")

        # Improved Captcha detection
        captcha_detected = False
        captcha_types = []
        for captcha_type, patterns in CAPTCHA_TYPES.items():
            if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                captcha_detected = True
                captcha_types.append(f"🤖 {captcha_type}")

        # Improved Cloudflare detection
        cloudflare_detected = bool(re.search(r"cloudflare-nginx|__cfduid|cf-ray|cloudflare-nginx", html, re.IGNORECASE)) or \
                              'cf-ray' in response.headers or \
                              any('cloudflare' in header.lower() for header in response.headers)

        # Enhanced security checks
        security_features = []
        if re.search(r"3D(-|\s)?Secure", html, re.IGNORECASE):
            security_features.append("🔒 3D Secure")
        if re.search(r"CVV|CVC|Security Code", html, re.IGNORECASE):
            security_features.append("🔑 CVV Required")
        if re.search(r"ssl|tls|https", html, re.IGNORECASE):
            security_features.append("🔐 SSL/TLS")
        if re.search(r"encryption|encrypted", html, re.IGNORECASE):
            security_features.append("🛡️ Encryption")
        if re.search(r"firewall", html, re.IGNORECASE):
            security_features.append("🧱 Firewall")
        if re.search(r"secure\s+payment|security\s+verified", html, re.IGNORECASE):
            security_features.append("✅ Secure Payment")
        if re.search(r"PCI|DSS", html, re.IGNORECASE):
            security_features.append("💳 PCI DSS")
        if re.search(r"fraud|protection", html, re.IGNORECASE):
            security_features.append("🚫 Fraud Protection")
        if re.search(r"verified\s+by\s+visa", html, re.IGNORECASE):
            security_features.append("💠 Verified by Visa")
        if re.search(r"mastercard\s+secure\s+code", html, re.IGNORECASE):
            security_features.append("🔰 Mastercard SecureCode")

        return {
            "status_code": status_code,
            "status_icon": status_icon,
            "gateways": gateways_found,
            "captcha": {
                "detected": captcha_detected,
                "types": captcha_types
            },
            "cloudflare": cloudflare_detected,
            "security_features": security_features,
        }

    except Exception as e:
        return {"error": f"{str(e)}"}


@app.on_message(filters.command("start"))
async def start_command(client, message: Message):
    user_id = message.from_user.id
    if user_id not in registered_users:
        start_text = (
            "━━━━━━ 𝗚𝗮𝘁𝗲𝘄𝗮𝘆 𝗖𝗵𝗲𝗰𝗸𝗲𝗿 ━━━━━━\n\n"
            "🌟 Welcome to Gateway Checker Bot!\n\n"
            "📝 To get started:\n"
            "➜ Use /register command\n\n"
            "🔥 Available features:\n"
            "➜ Check URLs with /chk\n"
            "➜ Process bulk URLs with /txt\n"
            "➜ Search URLs with /search\n"
            "➜ Learn more with /about\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "🛡️ Stay secure and happy checking!"
        )
        await message.reply(start_text, reply_to_message_id=message.id)
    else:
        welcome_back = (
            "━━━━━━ 𝗚𝗮𝘁𝗲𝘄𝗮𝘆 𝗖𝗵𝗲𝗰𝗸𝗲𝗿 ━━━━━━\n\n"
            "🎉 Welcome back!\n\n"
            "🚀 Available Commands:\n"
            "➜ /chk - Check URLs\n"
            "➜ /txt - Process bulk URLs\n"
            "➜ /search - Search URLs\n"
            "➜ /about - Bot information\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "💫 Let's get started!"
        )
        await message.reply(welcome_back, reply_to_message_id=message.id)


@app.on_message(filters.command("register"))
async def register_command(client, message: Message):
    user_id = message.from_user.id
    if user_id not in registered_users:
        registered_users.add(user_id)
        user_info = (
            "━━━━━━ 𝗡𝗲𝘄 𝗨𝘀𝗲𝗿 ━━━━━━\n\n"
            f"👤 Name: {message.from_user.first_name}\n"
            f"🔖 Username: @{message.from_user.username}\n"
            f"🆔 ID: `{user_id}`\n"
            "━━━━━━━━━━━━━━━━━━━━━━"
        )
        await client.send_message(ADMIN_ID, user_info)
        
        success_msg = (
            "━━━━━━ 𝗥𝗲𝗴𝗶𝘀𝘁𝗿𝗮𝘁𝗶𝗼𝗻 ━━━━━━\n\n"
            "✅ Registration Successful!\n\n"
            "🚀 Available Commands:\n"
            "➜ /chk - Check URLs\n"
            "➜ /txt - Process bulk URLs\n"
            "➜ /search - Search URLs\n"
            "➜ /about - Bot information\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "🎯 Ready to start checking!"
        )
        await message.reply(success_msg, reply_to_message_id=message.id)
    else:
        already_reg = (
            "━━━━━━ 𝗥𝗲𝗴𝗶𝘀𝘁𝗿𝗮𝘁𝗶𝗼𝗻 ━━━━━━\n\n"
            "ℹ️ You're already registered!\n\n"
            "Need help? Use /about for more information.\n"
            "━━━━━━━━━━━━━━━━━━━━━━"
        )
        await message.reply(already_reg, reply_to_message_id=message.id)


@app.on_message(filters.command("search"))
async def search_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply(
            "━━━━━━ 𝗔𝗰𝗰𝗲𝘀𝘀 𝗗𝗲𝗻𝗶𝗲𝗱 ━━━━━━\n\n"
            "🚫 You need to register first.\n"
            "➜ Use /register command\n"
            "━━━━━━━━━━━━━━━━━━━━━━", 
            reply_to_message_id=message.id
        )
        return

    try:
        # Improved parsing of command arguments
        args = shlex.split(message.text)
        if len(args) < 2:
            await message.reply(
                "━━━━━━ 𝗦𝗲𝗮𝗿𝗰𝗵 𝗛𝗲𝗹𝗽 ━━━━━━\n\n"
                "📝 Usage:\n"
                "/search <query> [amount]\n\n"
                "📌 Examples:\n"
                "➜ /search intext:\"payment\" 10\n"
                "➜ /search site:example.com 5\n"
                "➜ /search \"payment gateway\"\n"
                "━━━━━━━━━━━━━━━━━━━━━━"
            )
            return

        query = ' '.join(args[1:-1]) if args[-1].isdigit() else ' '.join(args[1:])
        amount = int(args[-1]) if args[-1].isdigit() else 10

        if amount < 1:
            amount = 10

        # Send initial status
        status_msg = await message.reply(
            "━━━━━━ 𝗦𝗲𝗮𝗿𝗰𝗵𝗶𝗻𝗴 ━━━━━━\n\n"
            "🔍 Processing your request...\n"
            "⏳ Please wait...\n"
            "━━━━━━━━━━━━━━━━━━━━━━"
        )

        # Perform Google search with improved parameters
        search_params = {
            'q': query,
            'num': amount,
            'hl': 'en',
            'gl': 'us',
            'safe': 'off',
            'start': 0,
            'filter': 0
        }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        urls = []
        async with aiohttp.ClientSession() as session:
            while len(urls) < amount:
                async with session.get('https://www.google.com/search', params=search_params, headers=headers) as response:
                    if response.status == 200:
                        html_content = await response.text()
                        soup = BeautifulSoup(html_content, 'html.parser')
                        search_results = soup.find_all('div', class_='yuRUbf')
                        
                        for result in search_results:
                            url = result.find('a')['href']
                            if url not in urls:
                                urls.append(url)
                                if len(urls) == amount:
                                    break
                    else:
                        break
                        
                search_params['start'] += 10
                await asyncio.sleep(1)

        if not urls:
            await status_msg.edit(
                "━━━━━━ 𝗡𝗼 𝗥𝗲𝘀𝘂𝗹𝘁𝘀 ━━━━━━\n\n"
                "❌ No URLs found!\n"
                "🔄 Try a different search query.\n"
                "━━━━━━━━━━━━━━━━━━━━━━"
            )
            return

        # Format results
        if amount <= 10:
            result_text = (
                "━━━━━━ 𝗦𝗲𝗮𝗿𝗰𝗵 𝗥𝗲𝘀𝘂𝗹𝘁𝘀 ━━━━━━\n\n"
                f"🔎 Query: {query}\n"
                f"📊 Found: {len(urls)} URLs\n\n"
                "📋 URLs List:\n"
            )

            for i, url in enumerate(urls, 1):
                result_text += f"{i}. {url}\n"

            result_text += "\n━━━━━━━━━━━━━━━━━━━━━━"
            await status_msg.edit(result_text)
        else:
            # Create a text file for bulk results
            file_name = f"search_results_{message.from_user.id}.txt"
            with open(file_name, "w") as f:
                for url in urls:
                    f.write(f"{url}\n")

            # Send the file
            await message.reply_document(
                document=file_name,
                caption=(
                    "━━━━━━ 𝗦𝗲𝗮𝗿𝗰𝗵 𝗥𝗲𝘀𝘂𝗹𝘁𝘀 ━━━━━━\n\n"
                    f"🔎 Query: {query}\n"
                    f"📊 Found: {len(urls)} URLs\n"
                    "━━━━━━━━━━━━━━━━━━━━━━"
                ),
                reply_to_message_id=message.id
            )

            os.remove(file_name)
            await status_msg.delete()

    except Exception as e:
        await message.reply(
            "━━━━━━ 𝗘𝗿𝗿𝗼𝗿 ━━━━━━\n\n"
            f"❌ Error: {str(e)}\n"
            "━━━━━━━━━━━━━━━━━━━━━━",
            reply_to_message_id=message.id
        )


@app.on_message(filters.command("about"))
async def about_command(client, message: Message):
    if message.from_user.id == ADMIN_ID:
        about_text = (
            "━━━━━━ 𝗚𝗮𝘁𝗲𝘄𝗮𝘆 𝗖𝗵𝗲𝗰𝗸𝗲𝗿 ━━━━━━\n\n"
            "🤖 Bot Features:\n"
            "➜ Multiple URL checking\n"
            "➜ Bulk processing via text file\n"
            "➜ Advanced gateway detection\n"
            "➜ Captcha and security analysis\n"
            "➜ URL search functionality\n\n"
            "📋 Commands:\n"
            "➜ /chk - Check URLs (up to 15)\n"
            "➜ /txt - Process URLs from file\n"
            "➜ /search - Search for URLs\n"
            "➜ /ban - Ban a user (Admin only)\n\n"
            "💳 Supported Gateways:\n"
            "➜ Stripe, Braintree, PayPal\n"
            "➜ Square, Amazon Pay, Klarna\n"
            "➜ Adyen, Authorize.net, Worldpay\n"
            "➜ Cybersource, 2Checkout, Eway\n"
            "➜ NMI, WooCommerce\n\n"
            "🛡️ Security Checks:\n"
            "➜ Multiple Captcha Systems\n"
            "➜ Cloudflare Protection\n"
            "➜ SSL/TLS Verification\n"
            "➜ 3D Secure Detection\n"
            "➜ PCI DSS Compliance\n"
            "━━━━━━━━━━━━━━━━━━━━━━"
        )
    else:
        about_text = (
            "━━━━━━ 𝗚𝗮𝘁𝗲𝘄𝗮𝘆 𝗖𝗵𝗲𝗰𝗸𝗲𝗿 ━━━━━━\n\n"
            "🤖 Bot Features:\n"
            "➜ Multiple URL checking\n"
            "➜ Bulk processing via text file\n"
            "➜ Advanced gateway detection\n"
            "➜ Captcha and security analysis\n"
            "➜ URL search functionality\n\n"
            "📋 Commands:\n"
            "➜ /chk - Check URLs (up to 15)\n"
            "➜ /txt - Process URLs from file\n"
            "➜ /search - Search for URLs\n\n"
            "💳 Supported Gateways:\n"
            "➜ Stripe, Braintree, PayPal\n"
            "➜ Square, Amazon Pay, Klarna\n"
            "➜ Adyen, Authorize.net, Worldpay\n"
            "➜ Cybersource, 2Checkout, Eway\n"
            "➜ NMI, WooCommerce\n\n"
            "🛡️ Security Checks:\n"
            "➜ Multiple Captcha Systems\n"
            "➜ Cloudflare Protection\n"
            "➜ SSL/TLS Verification\n"
            "➜ 3D Secure Detection\n"
            "➜ PCI DSS Compliance\n"
            "━━━━━━━━━━━━━━━━━━━━━━"
        )
    await message.reply(about_text, reply_to_message_id=message.id)


@app.on_message(filters.command("chk"))
async def chk_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply(
            "━━━━━━ 𝗔𝗰𝗰𝗲𝘀𝘀 𝗗𝗲𝗻𝗶𝗲𝗱 ━━━━━━\n\n"
            "🚫 You need to register first.\n"
            "➜ Use /register command\n"
            "━━━━━━━━━━━━━━━━━━━━━━", 
            reply_to_message_id=message.id
        )
        return

    # Extract URLs from the message
    if message.reply_to_message:
        text = message.reply_to_message.text or message.reply_to_message.caption
    else:
        text = message.text

    # Use regex to find URLs in the text
    urls = re.findall(r'https?://\S+', text)

    if not urls:
        await message.reply(
            "━━━━━━ 𝗡𝗼 𝗨𝗥𝗟𝘀 ━━━━━━\n\n"
            "📝 Usage:\n"
            "/chk <URL1> <URL2> ...\n\n"
            "📌 Examples:\n"
            "➜ /chk https://example.com\n"
            "➜ /chk https://example1.com https://example2.com\n"
            "━━━━━━━━━━━━━━━━━━━━━━",
            reply_to_message_id=message.id
        )
        return

    if len(urls) > 15:
        await message.reply(
            "━━━━━━ 𝗟𝗶𝗺𝗶𝘁 𝗘𝘅𝗰𝗲𝗲𝗱𝗲𝗱 ━━━━━━\n\n"
            "❌ Maximum 15 URLs allowed.\n"
            "━━━━━━━━━━━━━━━━━━━━━━", 
            reply_to_message_id=message.id
        )
        return

    response = await message.reply(
        "━━━━━━ 𝗚𝗮𝘁𝗲𝘄𝗮𝘆 𝗖𝗵𝗲𝗰𝗸𝗲𝗿 ━━━━━━\n", 
        reply_to_message_id=message.id
    )
    
    results = []

    for url in urls:
        result = await check_gateway(url)
        if "Let me continue from the exact cut-off point:

```python
for url in urls:
        result = await check_gateway(url)
        if "error" in result:
            gateway_info = (
                f"━━━━━━ 𝗚𝗮𝘁𝗲𝘄𝗮𝘆 𝗖𝗵𝗲𝗰𝗸 ━━━━━━\n\n"
                f"❌ Error Checking Gateway\n"
                f"🌐 URL: {url}\n"
                f"⚠️ Error: {result['error']}\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
            )
        else:
            gateway_info = (
                f"━━━━━━ 𝗚𝗮𝘁𝗲𝘄𝗮𝘆 𝗖𝗵𝗲𝗰𝗸 ━━━━━━\n\n"
                f"🌐 URL: {url}\n"
                f"💳 Gateways: {', '.join(result['gateways']) if result['gateways'] else '❌ None'}\n"
                f"🤖 Captcha: {('⚠️ Yes - ' + ', '.join(result['captcha']['types'])) if result['captcha']['detected'] else '✅ No'}\n"
                f"⚡ Cloudflare: {'✅ Yes' if result['cloudflare'] else '❌ No'}\n"
                f"🛡️ Security: {', '.join(result['security_features']) if result['security_features'] else '❌ None detected'}\n"
                f"📊 Status: {result['status_code']} {result['status_icon']}\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
            )
        
        results.append(gateway_info)
        
        full_message = "━━━━━━ 𝗚𝗮𝘁𝗲𝘄𝗮𝘆 𝗖𝗵𝗲𝗰𝗸𝗲𝗿 ━━━━━━\n\n" + "".join(results)
        
        try:
            await response.edit(full_message)
        except Exception as e:
            response = await message.reply(full_message, 
                                        reply_to_message_id=message.id)


@app.on_message(filters.command("txt") & filters.reply)
async def txt_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply(
            "━━━━━━ 𝗔𝗰𝗰𝗲𝘀𝘀 𝗗𝗲𝗻𝗶𝗲𝗱 ━━━━━━\n\n"
            "🚫 You need to register first.\n"
            "➜ Use /register command\n"
            "━━━━━━━━━━━━━━━━━━━━━━", 
            reply_to_message_id=message.id
        )
        return

    replied_message = message.reply_to_message
    if not replied_message.document or not replied_message.document.file_name.endswith('.txt'):
        await message.reply(
            "━━━━━━ 𝗜𝗻𝘃𝗮𝗹𝗶𝗱 𝗙𝗶𝗹𝗲 ━━━━━━\n\n"
            "📝 Usage:\n"
            "Reply to a .txt file containing URLs (one per line).\n\n"
            "📌 Example:\n"
            "1. Create a file urls.txt with URLs:\n"
            "https://example1.com\n"
            "https://example2.com\n"
            "2. Reply to the file with /txt\n"
            "━━━━━━━━━━━━━━━━━━━━━━",
            reply_to_message_id=message.id
        )
        return

    file = await replied_message.download()
    with open(file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    os.remove(file)

    if not urls:
        await message.reply(
            "━━━━━━ 𝗡𝗼 𝗨𝗥𝗟𝘀 ━━━━━━\n\n"
            "❌ No valid URLs found in the file.\n"
            "━━━━━━━━━━━━━━━━━━━━━━", 
            reply_to_message_id=message.id
        )
        return

    total_urls = len(urls)
    response = await message.reply(
        f"━━━━━━ 𝗠𝗮𝘀𝘀 𝗖𝗵𝗲𝗰𝗸𝗲𝗿 ━━━━━━\n\n"
        f"📊 Found: {total_urls} URLs\n"
        f"⏳ Status: Starting check...\n"
        f"━━━━━━━━━━━━━━━━━━━━━━", 
        reply_to_message_id=message.id
    )

    results = {gateway: [] for gateway in GATEWAYS.keys()}
    checked = 0
    found_gateways = set()

    async def update_message():
        while checked < total_urls:
            await asyncio.sleep(2)
            remaining = total_urls - checked
            progress = int((checked / total_urls) * 20)
            progress_bar = '█' * progress + '░' * (20 - progress)
            percentage = int((checked / total_urls) * 100)
            
            status_lines = [
                "━━━━━━ 𝗠𝗮𝘀𝘀 𝗖𝗵𝗲𝗰𝗸𝗲𝗿 ━━━━━━\n\n"
                f"📊 Progress: [{progress_bar}] {percentage}%\n"
                f"✓ Checked: {checked}/{total_urls}\n"
                f"⏳ Remaining: {remaining}\n\n"
            ]
            
            if found_gateways:
                status_lines.append("💳 Found Gateways:\n")
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
        if "error" not in result and result["gateways"]:
            for gateway in result["gateways"]:
                results[gateway].append(url)
                found_gateways.add(gateway)

    update_task.cancel()

    # Send final results
    for gateway, urls in results.items():
        if urls:
            url_list = '\n'.join(f'➜ {url}' for url in urls)
            result_text = (
                f"━━━━━━ {gateway} 𝗛𝗶𝘁𝘀 ━━━━━━\n\n"
                f"{url_list}\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
            )
            try:
                await message.reply(result_text, reply_to_message_id=message.id)
            except Exception:
                # Handle long messages by splitting into chunks
                chunks = [urls[i:i + 50] for i in range(0, len(urls), 50)]
                for i, chunk in enumerate(chunks):
                    chunk_list = '\n'.join(f'➜ {url}' for url in chunk)
                    chunk_text = (
                        f"━━━━━━ {gateway} 𝗛𝗶𝘁𝘀 (𝗣𝗮𝗿𝘁 {i+1}) ━━━━━━\n\n"
                        f"{chunk_list}\n"
                        f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
                    )
                    await message.reply(chunk_text, reply_to_message_id=message.id)

    final_status = (
        "━━━━━━ 𝗖𝗵𝗲𝗰𝗸 𝗖𝗼𝗺𝗽𝗹𝗲𝘁𝗲𝗱 ━━━━━━\n\n"
        f"📊 Total URLs: {total_urls}\n\n"
    )

    if found_gateways:
        final_status += "💳 Gateway Hits:\n"
        for gateway in found_gateways:
            final_status += f"➜ {gateway}: {len(results[gateway])}\n"
        final_status += "\n━━━━━━━━━━━━━━━━━━━━━━"

    await response.edit(final_status)


@app.on_message(filters.command("ban") & filters.user(ADMIN_ID))
async def ban_command(client, message: Message):
    try:
        # Parse command arguments
        args = message.text.split()
        if len(args) != 2:
            await message.reply(
                "━━━━━━ 𝗕𝗮𝗻 𝗖𝗼𝗺𝗺𝗮𝗻𝗱 ━━━━━━\n\n"
                "📝 Usage:\n"
                "/ban <user_id>\n\n"
                "📌 Example:\n"
                "/ban 123456789\n"
                "━━━━━━━━━━━━━━━━━━━━━━",
                reply_to_message_id=message.id
            )
            return

        user_id = int(args[1])
        
        if user_id in registered_users:
            registered_users.remove(user_id)
            await message.reply(
                "━━━━━━ 𝗕𝗮𝗻 𝗦𝘂𝗰𝗰𝗲𝘀𝘀𝗳𝘂𝗹 ━━━━━━\n\n"
                f"✅ User with ID {user_id} has been banned.\n"
                "━━━━━━━━━━━━━━━━━━━━━━", 
                reply_to_message_id=message.id
            )
        else:
            await message.reply(
                "━━━━━━ 𝗕𝗮𝗻 𝗙𝗮𝗶𝗹𝗲𝗱 ━━━━━━\n\n"
                f"❌ User with ID {user_id} is not registered.\n"
                "━━━━━━━━━━━━━━━━━━━━━━", 
                reply_to_message_id=message.id
            )

    except ValueError:
        await message.reply(
            "━━━━━━ 𝗜𝗻𝘃𝗮𝗹𝗶𝗱 𝗜𝗗 ━━━━━━\n\n"
            "❌ Please provide a valid numeric user ID.\n"
            "━━━━━━━━━━━━━━━━━━━━━━", 
            reply_to_message_id=message.id
        )
    except Exception as e:
        await message.reply(
            "━━━━━━ 𝗘𝗿𝗿𝗼𝗿 ━━━━━━\n\n"
            f"❌ An error occurred: {str(e)}\n"
            "━━━━━━━━━━━━━━━━━━━━━━", 
            reply_to_message_id=message.id
        )

# Run the bot
app.run()

