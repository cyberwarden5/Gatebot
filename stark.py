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
        # Script sources
        r"<script[^>]*src=['\"]https?://js\.stripe\.com/v\d/['\"]",
        r"<script[^>]*src=['\"]https?://r\.stripe\.com/b['\"]",
        # API endpoints
        r"stripe\.com/v\d/tokens",
        r"stripe\.com/v\d/payment_intents",
        r"checkout\.stripe\.com",
        # JavaScript variables and functions
        r"Stripe$$(['\"](pk_live|pk_test)_[0-9a-zA-Z]+['\"]$$",
        r"stripe\.createToken",
        r"stripe\.confirmCardPayment",
    ],
    "Braintree": [
        r"<script[^>]*src=['\"]https?://js\.braintreegateway\.com/[^'\"]+['\"]",
        r"braintree\.setup",
        r"braintreepayments\.com",
        r"braintree\.client\.create",
        r"braintree\.paypal\.create",
    ],
    "PayPal": [
        r"paypal\.com/sdk/js",
        r"paypal\.Buttons",
        r"www\.paypal\.com",
        r"pay\.paypal\.com",
        r"paypal-button",
    ],
    "Square": [
        r"squareup\.com/payments",
        r"SqPaymentForm",
        r"cash\.me",
        r"square\.com/js",
    ],
    "Amazon Pay": [
        r"pay\.amazon\.com",
        r"amazon-pay",
        r"amazonpay",
    ],
    "Apple Pay": [
        r"pay\.apple\.com",
        r"apple-pay",
        r"applepay",
    ],
    "Google Pay": [
        r"pay\.google\.com",
        r"google-pay",
        r"googlepay",
    ],
    "Adyen": [
        r"checkoutshopper-live\.adyen\.com",
        r"adyen\.com",
    ],
    "Authorize.net": [
        r"accept\.authorize\.net",
        r"AcceptUI",
        r"authorize\.net",
    ],
    "2Checkout": [
        r"2checkout\.com",
        r"2co\.com",
    ],
    "Klarna": [
        r"klarna\.com",
        r"klarna-payments",
    ],
}

# Platform detection patterns
PLATFORMS = {
    "WordPress": [
        r"wp-content",
        r"wp-includes",
        r"wp-admin",
    ],
    "Shopify": [
        r"myshopify\.com",
        r"shopify\.com",
        r"shopify-store",
    ],
    "Magento": [
        r"magento",
        r"mage-init",
    ],
    "WooCommerce": [
        r"woocommerce",
        r"wc-api",
        r"wc-ajax",
    ],
    "PrestaShop": [
        r"prestashop",
        r"presta-shop",
    ],
    "OpenCart": [
        r"opencart",
        r"route=common",
    ],
    "Joomla": [
        r"joomla",
        r"option=com_",
    ],
    "Custom PHP": [
        r"\.php",
        r"php-script",
    ],
}

# Captcha detection patterns
CAPTCHA_TYPES = {
    "reCAPTCHA": [
        r"www\.google\.com/recaptcha",
        r"grecaptcha",
        r"g-recaptcha",
    ],
    "hCaptcha": [
        r"hcaptcha\.com",
        r"h-captcha",
    ],
    "Arkose Labs": [
        r"arkoselabs\.com",
        r"funcaptcha",
    ],
    "Custom Captcha": [
        r"captcha\.php",
        r"custom-captcha",
    ],
}

# Store registered users
registered_users = set()

async def check_gateway(url):
    """
    Enhanced gateway checking with advanced detection methods
    """
    try:
        async with aiohttp.ClientSession() as session:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            async with session.get(url, ssl=False, timeout=15, headers=headers) as response:
                html = await response.text()
                status_code = response.status
                resp_headers = response.headers

                soup = BeautifulSoup(html, 'html.parser')

                # Gateway detection
                gateways_found = []
                for gateway, patterns in GATEWAYS.items():
                    if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                        gateways_found.append(gateway)

                # Platform detection
                platform_found = []
                for platform, patterns in PLATFORMS.items():
                    if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                        platform_found.append(platform)

                # Captcha detection and type identification
                captcha_found = False
                captcha_types = []
                for c_type, patterns in CAPTCHA_TYPES.items():
                    if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                        captcha_found = True
                        captcha_types.append(c_type)

                # Security checks
                cloudflare = any([
                    "cloudflare" in html.lower(),
                    "__cf_" in html,
                    "cf-ray" in resp_headers,
                    "cf-cache-status" in resp_headers,
                ])

                security_features = {
                    "SSL": url.startswith("https"),
                    "CSP": bool(resp_headers.get("Content-Security-Policy")),
                    "HSTS": bool(resp_headers.get("Strict-Transport-Security")),
                    "XSS Protection": bool(resp_headers.get("X-XSS-Protection")),
                }

                return {
                    "status_code": status_code,
                    "gateways": gateways_found,
                    "platform": platform_found[0] if platform_found else "Unknown",
                    "captcha": {
                        "detected": captcha_found,
                        "types": captcha_types
                    },
                    "cloudflare": cloudflare,
                    "security": security_features,
                    "headers": dict(resp_headers)
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
        "➜ Klarna 🛍️\n\n"
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
                f"➜ **Payment Gateways:** {', '.join(result['gateways']) if result['gateways'] else 'None'}\n"
                f"➜ **Platform:** {result['platform']}\n"
                f"➜ **Captcha Detected:** {'⚠️ Yes' if result['captcha']['detected'] else 'No'}\n"
                f"{captcha_info if result['captcha']['detected'] else ''}"
                f"➜ **Cloudflare:** {'⚡ Yes' if result['cloudflare'] else 'No'}\n"
                f"➜ **Security Features:**\n"
                f"   • SSL: {'✅' if result['security']['SSL'] else '❌'}\n"
                f"   • CSP: {'✅' if result['security']['CSP'] else '❌'}\n"
                f"   • HSTS: {'✅' if result['security']['HSTS'] else '❌'}\n"
                f"   • XSS Protection: {'✅' if result['security']['XSS Protection'] else '❌'}\n"
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
        if "error" not in result and result["gateways"]:
            for gateway in result["gateways"]:
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

