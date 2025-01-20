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
#import brotli
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

# Store registered users
registered_users = set()

async def check_gateway(url):
    """
    Enhanced gateway checking with advanced detection methods using cloudscraper
    """
    try:
        scraper = cloudscraper.create_scraper()
        response = scraper.get(url, timeout=15)

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

#import shlex

@app.on_message(filters.command("search"))
async def search_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply("🚫 You need to register first. Please use the /register command.", 
                          reply_to_message_id=message.id)
        return

    try:
        # Parse command arguments
        args = shlex.split(message.text)
        if len(args) < 2:
            await message.reply(
                "❌ **Invalid Format!**\n\n"
                "📝 **Usage:**\n"
                "`/search <query> [amount]`\n\n"
                "📌 **Example:**\n"
                "`/search intext:\"payment\" 10`",
                reply_to_message_id=message.id
            )
            return

        query = args[1]
        amount = 10  # Default amount

        if len(args) == 3:
            try:
                amount = int(args[2])
                if amount < 1:
                    amount = 10
            except ValueError:
                amount = 10

        # Send initial status
        status_msg = await message.reply(
            "🔍 **Searching URLs...**\n"
            "Please wait...",
            reply_to_message_id=message.id
        )

        # Perform Google search
        urls = list(search(query, num=amount, stop=amount, pause=2))

        if not urls:
            await status_msg.edit(
                "❌ **No Results Found!**\n"
                "Try a different search query."
            )
            return

        # Format results
        if amount <= 10:
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
        else:
            # Create a text file with URLs
            file_name = f"search_results_{message.from_user.id}.txt"
            with open(file_name, "w") as f:
                for url in urls:
                    f.write(f"{url}\n")

            # Send the file
            await message.reply_document(
                document=file_name,
                caption=f"🔍 **Search Results**\n"
                        f"━━━━━━━━━━━━━━━━━━━━\n"
                        f"🔎 **Query:** `{query}`\n"
                        f"📊 **Found:** `{len(urls)}` URLs\n"
                        f"━━━━━━━━━━━━━━━━━━━━",
                reply_to_message_id=message.id
            )

            # Delete the temporary file
            os.remove(file_name)

            await status_msg.delete()

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
        "➜ Captcha and security analysis\n"
        "➜ URL search functionality\n\n"
        "📋 **Commands:**\n"
        "➜ /chk - Check URLs (up to 15)\n"
        "➜ /txt - Process URLs from file\n"
        "➜ /search - Search for URLs\n\n"
        "💳 **Supported Gateways:**\n"
        "➜ Stripe, Braintree, PayPal, Square\n"
        "➜ Amazon Pay, Klarna, Adyen\n"
        "➜ Authorize.net, Worldpay, Cybersource\n"
        "➜ 2Checkout, Eway, NMI, WooCommerce\n\n"
        "🛡️ **Security Checks:**\n"
        "➜ Captcha Systems\n"
        "➜ Cloudflare Protection\n"
        "➜ Payment Security Types\n"
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
            gateway_info = (
                f"🔍 **Gateway Fetched Successfully** ✅\n"
                f"━━━━━━━━━━━━━━\n"
                f"➜ **URL:** `{url}`\n"
                f"➜ **Payment Gateways:** {', '.join(result['gateways']) if result['gateways'] else 'None'}\n"
                f"➜ **Captcha Detected:** {'⚠️ Yes' if result['captcha']['detected'] else 'No'}\n"
                f"➜ **Captcha Types:** {', '.join(result['captcha']['types']) if result['captcha']['detected'] else 'N/A'}\n"
                f"➜ **Cloudflare:** {'⚡ Yes' if result['cloudflare'] else 'No'}\n"
                f"➜ **Payment Security:** {', '.join(result['payment_security']) if result['payment_security'] else 'None detected'}\n"
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
            url_list = '\n'.join(f'`{url}`' for url in urls)
            result_text = (
                f"🔍 **{gateway} Hits**\n"
                f"━━━━━━━━━━━━━━\n"
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
                        f"🔍 **{gateway} Hits (Part {i+1})**\n"
                        f"━━━━━━━━━━━━━━\n"
                        f"{chunk_list}"
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
