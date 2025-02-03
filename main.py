import re
import asyncio
from pyrogram import Client, filters
from pyrogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton
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

# Gateway and captcha patterns remain the same
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
        scraper = cloudscraper.create_scraper()
        response = await asyncio.to_thread(scraper.get, url, timeout=15)

        html = response.text
        status_code = response.status_code

        # Gateway detection
        gateways_found = []
        for gateway, patterns in GATEWAYS.items():
            if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                gateways_found.append(gateway)

        # Captcha detection
        captcha_detected = False
        captcha_types = []
        for captcha_type, patterns in CAPTCHA_TYPES.items():
            if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                captcha_detected = True
                captcha_types.append(captcha_type)

        # Cloudflare detection
        cloudflare_detected = bool(re.search(r"cloudflare", html, re.IGNORECASE))

        # Payment security types (simplified check)
        payment_security = []
        if re.search(r"3D(-|\s)?Secure", html, re.IGNORECASE):
            payment_security.append("3D Secure")
        if re.search(r"CVV|CVC|Security Code", html, re.IGNORECASE):
            payment_security.append("CVV Required")

        return {
            "status_code": status_code,
            "gateways": gateways_found,
            "captcha": {
                "detected": captcha_detected,
                "types": captcha_types
            },
            "cloudflare": cloudflare_detected,
            "payment_security": payment_security,
        }

    except Exception as e:
        return {"error": f"❌ Unexpected error: {str(e)}"}

@app.on_message(filters.command("start"))
async def start_command(client, message: Message):
    user_id = message.from_user.id
    if user_id not in registered_users:
        start_text = (
            "🌟 **Welcome to Gateway Checker Bot!** 🌟\n\n"
            "Unlock the power of payment gateway detection with ease.\n\n"
            "🚀 **Quick Start:**\n"
            "1️⃣ Register with /register\n"
            "2️⃣ Check URLs with /chk\n"
            "3️⃣ Process bulk URLs with /txt\n"
            "4️⃣ Search URLs with /search\n\n"
            "🔍 Ready to explore? Let's get started!"
        )
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("Register Now", callback_data="register")]
        ])
        await message.reply(start_text, reply_markup=keyboard, reply_to_message_id=message.id)
    else:
        welcome_back = (
            "👋 **Welcome back, gateway explorer!**\n\n"
            "Ready to uncover more payment gateways?\n\n"
            "🛠 **Your Toolkit:**\n"
            "🔍 /chk - Analyze URLs\n"
            "📚 /txt - Bulk URL processing\n"
            "🔎 /search - Discover new URLs\n"
            "ℹ️ /about - Bot insights\n\n"
            "Let's dive in and discover!"
        )
        await message.reply(welcome_back, reply_to_message_id=message.id)

@app.on_callback_query(filters.regex("^register$"))
async def register_callback(client, callback_query):
    await register_command(client, callback_query.message)

@app.on_message(filters.command("register"))
async def register_command(client, message: Message):
    user_id = message.from_user.id
    if user_id not in registered_users:
        registered_users.add(user_id)
        user_info = (
            "🆕 **New Explorer Joined!**\n"
            f"👤 **Name:** {message.from_user.first_name}\n"
            f"🔖 **Username:** @{message.from_user.username}\n"
            f"🆔 **ID:** `{user_id}`"
        )
        await client.send_message(ADMIN_ID, user_info)
        
        success_msg = (
            "🎉 **Welcome aboard, Gateway Explorer!**\n\n"
            "You're now part of an elite group of payment detectives.\n\n"
            "🚀 **Your Adventure Begins:**\n"
            "🔍 /chk - Analyze URLs\n"
            "📚 /txt - Bulk URL processing\n"
            "🔎 /search - Discover new URLs\n"
            "ℹ️ /about - Bot insights\n\n"
            "Ready to uncover the secrets of payment gateways?"
        )
        await message.reply(success_msg, reply_to_message_id=message.id)
    else:
        already_reg = (
            "🌟 **You're Already a Pro!**\n\n"
            "You're all set to explore the world of payment gateways.\n"
            "Need a refresher? Check /about for the latest features!"
        )
        await message.reply(already_reg, reply_to_message_id=message.id)

@app.on_message(filters.command("search"))
async def search_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply("🔐 Explorer, you need to register first! Use /register to join the adventure.", 
                          reply_to_message_id=message.id)
        return

    try:
        args = shlex.split(message.text)
        if len(args) < 2:
            await message.reply(
                "🔎 **URL Search Guide**\n\n"
                "📝 **Usage:**\n"
                "`/search <query> [amount]`\n\n"
                "🌟 **Pro Tips:**\n"
                "• `intext:\"payment\"` - Find pages with specific text\n"
                "• `site:example.com` - Search within a specific site\n"
                "• Use quotes for exact phrases\n\n"
                "🚀 **Examples:**\n"
                "• `/search intext:\"payment\" 10`\n"
                "• `/search site:example.com 5`\n"
                "• `/search \"payment gateway\"`",
                reply_to_message_id=message.id
            )
            return

        query = args[1]
        amount = 10 if len(args) < 3 else max(1, int(args[2]))

        status_msg = await message.reply(
            "🕵️ **Searching for Hidden Gateways...**\n"
            "Hang tight, detective!",
            reply_to_message_id=message.id
        )

        urls = list(search(query, num=amount, stop=amount, pause=2))

        if not urls:
            await status_msg.edit(
                "🔍 **The Search Continues...**\n"
                "No results found. Try a different query or search term."
            )
            return

        if amount <= 10:
            result_text = (
                f"🎉 **Gateway Leads Uncovered!**\n\n"
                f"🔍 **Your Query:** `{query}`\n"
                f"📊 **Discoveries:** `{len(urls)}` potential gateways\n\n"
                f"🌐 **URL Treasures:**\n"
            )
            for i, url in enumerate(urls, 1):
                result_text += f"{i}. `{url}`\n"
            await status_msg.edit(result_text)
        else:
            file_name = f"gateway_leads_{message.from_user.id}.txt"
            with open(file_name, "w") as f:
                for url in urls:
                    f.write(f"{url}\n")

            await message.reply_document(
                document=file_name,
                caption=(
                    f"🗺 **Your Gateway Treasure Map**\n\n"
                    f"🔍 **Quest:** `{query}`\n"
                    f"💎 **Discoveries:** `{len(urls)}` potential gateways\n\n"
                    "Unleash your detective skills on these URLs!"
                ),
                reply_to_message_id=message.id
            )
            os.remove(file_name)
            await status_msg.delete()

    except Exception as e:
        await message.reply(
            f"🚫 **Quest Interrupted**\n"
            f"Error: `{str(e)}`\n"
            "Let's regroup and try again!",
            reply_to_message_id=message.id
        )

@app.on_message(filters.command("about"))
async def about_command(client, message: Message):
    about_text = (
        "🛡 **Gateway Checker Bot: Your Payment Detective**\n\n"
        "Uncover the secrets of online payments with cutting-edge technology.\n\n"
        "🔮 **Magical Features:**\n"
        "• Multi-URL analysis\n"
        "• Bulk URL processing\n"
        "• Advanced gateway detection\n"
        "• Captcha & security insights\n"
        "• URL treasure hunting\n\n"
        "🧙‍♂️ **Spells (Commands):**\n"
        "• /chk - Analyze up to 15 URLs\n"
        "• /txt - Process URL scrolls (files)\n"
        "• /search - Discover new realms (URLs)\n\n"
        "💳 **Detectable Gateways:**\n"
        "Stripe, Braintree, PayPal, Square, Amazon Pay, Klarna, Adyen, "
        "Authorize.net, Worldpay, Cybersource, 2Checkout, Eway, NMI, WooCommerce\n\n"
        "🛡 **Security Insights:**\n"
        "• Captcha systems\n"
        "• Cloudflare shields\n"
        "• Payment security enchantments\n\n"
        "Ready to embark on your payment gateway quest?"
    )
    await message.reply(about_text, reply_to_message_id=message.id)

@app.on_message(filters.command("chk"))
async def chk_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply("🔐 Explorer, you need to register first! Use /register to join the adventure.", 
                          reply_to_message_id=message.id)
        return

    text = message.reply_to_message.text or message.reply_to_message.caption if message.reply_to_message else message.text
    urls = re.findall(r'https?://\S+', text)

    if not urls:
        await message.reply(
            "🕵️ **Gateway Detection Guide**\n\n"
            "📝 **Usage:**\n"
            "`/chk <URL1> <URL2> ...`\n\n"
            "🌟 **Examples:**\n"
            "• `/chk https://example.com`\n"
            "• `/chk https://shop1.com https://shop2.com`\n\n"
            "Ready to uncover some gateways?",
            reply_to_message_id=message.id
        )
        return

    if len(urls) > 15:
        await message.reply("🚀 Whoa, detective! Let's stick to 15 URLs max for now.", 
                          reply_to_message_id=message.id)
        return

    response = await message.reply("🔍 **Initiating Gateway Scan**\nPreparing to unveil the secrets...", 
                                 reply_to_message_id=message.id)
    results = []

    for url in urls:
        result = await check_gateway(url)
        if "error" in result:
            gateway_info = (
                f"🚫 **Gateway Scan Interrupted**\n"
                f"🌐 **URL:** `{url}`\n"
                f"❌ **Error:** `{result['error']}`\n\n"
            )
        else:
            gateway_info = (
                f"✨ **Gateway Insights Revealed**\n"
                f"🌐 **URL:** `{url}`\n"
                f"💳 **Payment Gateways:** {', '.join(result['gateways']) if result['gateways'] else 'None detected'}\n"
                f"🛡 **Captcha Shield:** {'⚠️ Active' if result['captcha']['detected'] else 'Inactive'}\n"
                f"🔒 **Captcha Types:** {', '.join(result['captcha']['types']) if result['captcha']['detected'] else 'N/A'}\n"
                f"☁️ **Cloudflare Guard:** {'⚡ Active' if result['cloudflare'] else 'Inactive'}\n"
                f"🔐 **Payment Security:** {', '.join(result['payment_security']) if result['payment_security'] else 'Standard'}\n"
                f"📊 **Response Code:** {result['status_code']}\n\n"
            )
        
        results.append(gateway_info)
        
        full_message = "🔍 **Gateway Detection Results**\n\n" + "".join(results)
        
        try:
            await response.edit(full_message)
        except Exception as e:
            response = await message.reply(full_message, 
                                        reply_to_message_id=message.id)

@app.on_message(filters.command("txt") & filters.reply)
async def txt_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply("🔐 Explorer, you need to register first! Use /register to join the adventure.", 
                          reply_to_message_id=message.id)
        return

    replied_message = message.reply_to_message
    if not replied_message.document or not replied_message.document.file_name.endswith('.txt'):
        await message.reply(
            "📜 **Bulk URL Analysis Guide**\n\n"
            "1️⃣ Create a text file with URLs (one per line)\n"
            "2️⃣ Send the file to this chat\n"
            "3️⃣ Reply to the file with `/txt`\n\n"
            "🌟 **Pro Tip:** Name your file `gateways_to_check.txt`",
            reply_to_message_id=message.id
        )
        return

    file = await replied_message.download()
    with open(file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    os.remove(file)

    if not urls:
        await message.reply("📭 Oops! Your treasure map (file) seems to be empty. Let's fill it with URLs and try again!", 
                          reply_to_message_id=message.id)
        return

    total_urls = len(urls)
    response = await message.reply(
        f"🚀 **Bulk Gateway Expedition Initiated**\n\n"
        f"🗺 **URLs to Explore:** {total_urls}\n"
        f"🕵️ **Status:** Gearing up for the adventure...\n\n"
        f"Hang tight, detective! We're about to uncover some gateway secrets.", 
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
                "🚀 **Bulk Gateway Expedition Update**\n\n"
                f"🗺 **Total URLs:** {total_urls}\n"
                f"✅ **Explored:** {checked}\n"
                f"🔍 **Remaining:** {remaining}\n\n"
            ]
            
            if found_gateways:
                status_lines.append("💳 **Gateways Discovered:**\n")
                for gateway in found_gateways:
                    status_lines.append(f"• {gateway}: {len(results[gateway])}\n")
            
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
            url_list = '\n'.join(f'`{url}`' for url in urls)
            result_text = (
                f"🎉 **{gateway} Gateways Uncovered!**\n\n"
                f"{url_list}"
            )
            try:
                await message.reply(result_text, reply_to_message_id=message.id)
            except Exception:
                # Handle long messages by splitting into chunks
                chunks = [urls[i:i + 50] for i in range(0, len(urls), 50)]
                for i, chunk in enumerate(chunks):
                    chunk_list = '\n'.join(f'`{url}`' for url in chunk)
                    chunk_text = (
                        f"🎉 **{gateway} Gateways (Part {i+1})**\n\n"
                        f"{chunk_list}"
                    )
                    await message.reply(chunk_text, reply_to_message_id=message.id)

    final_status = (
        "🏆 **Bulk Gateway Expedition Completed!**\n\n"
        f"📊 **Expedition Summary:**\n"
        f"• Total URLs Explored: {total_urls}\n"
    )

    if found_gateways:
        final_status += "\n💳 **Gateway Discoveries:**\n"
        for gateway in found_gateways:
            final_status += f"• {gateway}: {len(results[gateway])}\n"

    final_status += "\nGreat work, detective! Ready for your next mission?"
    await response.edit(final_status)

# Run the bot
app.run()

