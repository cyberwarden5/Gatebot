import re
import asyncio
from pyrogram import Client, filters
from pyrogram.types import Message
import aiohttp
import os
import warnings
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup

# Suppress SSL verification warnings
warnings.simplefilter('ignore', InsecureRequestWarning)

# Bot configuration
API_ID = 23883349
API_HASH = "9ae2939989ed439ab91419d66b61a4a4"
BOT_TOKEN = "7842856490:AAGK3IHkatwgNAliRjF1orLCyohjLEUVK9g"
ADMIN_ID = 5429071679

# Initialize the bot
app = Client("gateway_checker_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# Define the keywords and patterns for gateway checking
GATEWAYS = {
    "Stripe": [
        r"<script src=\"https://js.stripe.com/v3/\"></script>",
        r"<script src=\"https://r.stripe.com/b\"></script>",
        r"Stripe.setPublishableKey"
    ],
    "Braintree": [
        r"<script src=\"https://js.braintreegateway.com/v2/braintree.js\"></script>",
        r"braintree.setup"
    ],
    "Shopify": [
        r"var Shopify = Shopify \|\| {};",
        r"Shopify.shop"
    ],
    "PayPal": [
        r"paypal.com/sdk/js",
        r"paypal.Buttons"
    ],
    "Authorize.net": [
        r"accept.authorize.net",
        r"AcceptUI"
    ],
    "Square": [
        r"squareup.com/payments",
        r"SqPaymentForm"
    ],
    "Cybersource": [
        r"cybersource.com",
        r"Cybersource"
    ],
    "Eway": [
        r"eway.com.au",
        r"eWAY"
    ],
    "NMI": [
        r"secure.networkmerchants.com",
        r"CollectJS"
    ],
    "WooCommerce": [
        r"woocommerce",
        r"WC_AJAX"
    ]
}

# Store registered users
registered_users = set()

async def check_gateway(url):
    """
    Check a given URL for payment gateways and security features.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, ssl=False, timeout=10) as response:
                html = await response.text()
                status_code = response.status
                headers = response.headers

                soup = BeautifulSoup(html, 'html.parser')

                gateways_found = []
                for gateway, patterns in GATEWAYS.items():
                    if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                        gateways_found.append(gateway)

                # Advanced detection methods
                cloudflare_detected = "Yes" if any([
                    "cloudflare" in html.lower(),
                    "__cf_" in html,
                    "cf-ray" in headers,
                    soup.find('a', href=re.compile(r'cloudflare.com'))
                ]) else "No"

                captcha_detected = "Yes" if any([
                    re.search(r"captcha|recaptcha|hcaptcha", html, re.IGNORECASE),
                    soup.find('div', class_=re.compile(r'g-recaptcha|h-captcha')),
                    "grecaptcha" in html,
                    "hcaptcha" in html
                ]) else "No"

                payment_security = "3D" if any([
                    "3d-secure" in html.lower(),
                    "three-d-secure" in html.lower(),
                    re.search(r"Cardinal\.setup", html)
                ]) else "2D"

                cvv_required = "Required" if re.search(r"cvv|cvc|security code", html, re.IGNORECASE) else "Not Required"

                inbuilt_payment = "Yes" if any([
                    re.search(r"checkout|payment", html, re.IGNORECASE),
                    soup.find('form', id=re.compile(r'checkout|payment', re.IGNORECASE))
                ]) else "No"

                return {
                    "status_code": status_code,
                    "gateways": gateways_found,
                    "captcha": captcha_detected,
                    "cloudflare": cloudflare_detected,
                    "payment_security": payment_security,
                    "cvv": cvv_required,
                    "inbuilt_payment": inbuilt_payment
                }
    except asyncio.TimeoutError:
        return {"error": "Timeout"}
    except aiohttp.ClientError as e:
        return {"error": f"Connection error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

@app.on_message(filters.command("start"))
async def start_command(client, message: Message):
    user_id = message.from_user.id
    if user_id not in registered_users:
        start_text = (
            "🌟 **Welcome to Gateway Checker Bot!** 🌟\n\n"
            "🔐 To get started, please register using the /register command.\n\n"
            "📝 After registration, you can:\n"
            "• Check URLs with /chk\n"
            "• Process bulk URLs with /txt\n"
            "• Learn more with /about\n\n"
            "🛡️ Stay secure and happy checking!"
        )
        await message.reply(start_text)
    else:
        welcome_back = (
            "🎉 **Welcome back!** 🎉\n\n"
            "🔍 Ready to check some gateways?\n\n"
            "📋 **Available Commands:**\n"
            "• /chk - Check URLs\n"
            "• /txt - Process bulk URLs\n"
            "• /about - Bot information\n\n"
            "💫 Let's get started!"
        )
        await message.reply(welcome_back)

@app.on_message(filters.command("register"))
async def register_command(client, message: Message):
    user_id = message.from_user.id
    if user_id not in registered_users:
        registered_users.add(user_id)
        user_info = (
            "🆕 **New User Registration**\n"
            f"👤 **Name:** {message.from_user.first_name}\n"
            f"🔖 **Username:** @{message.from_user.username}\n"
            f"🆔 **ID:** `{user_id}`"
        )
        await client.send_message(ADMIN_ID, user_info)
        
        success_msg = (
            "✅ **Registration Successful!**\n\n"
            "🎉 Welcome to Gateway Checker Bot!\n\n"
            "📋 **Available Commands:**\n"
            "• /chk - Check URLs\n"
            "• /txt - Process bulk URLs\n"
            "• /about - Bot information\n\n"
            "🚀 Ready to start checking!"
        )
        await message.reply(success_msg)
    else:
        already_reg = (
            "ℹ️ **Already Registered**\n\n"
            "You're already registered and can use all bot features!\n\n"
            "Need help? Use /about for more information."
        )
        await message.reply(already_reg)

@app.on_message(filters.command("about"))
async def about_command(client, message: Message):
    about_text = (
        "🔍 **Gateway Checker Bot**\n"
        "━━━━━━━━━━━━━━\n\n"
        "🤖 **Bot Features:**\n"
        "• Multiple URL checking\n"
        "• Bulk processing via text file\n"
        "• Advanced gateway detection\n"
        "• Security measure analysis\n\n"
        "📋 **Commands:**\n"
        "• /chk - Check URLs (up to 15)\n"
        "• /txt - Process URLs from file\n\n"
        "💳 **Supported Gateways:**\n"
        "• Stripe 💳\n"
        "• Braintree 🧠\n"
        "• Shopify 🛒\n"
        "• PayPal 💰\n"
        "• Authorize.net 🔐\n"
        "• Square ◻️\n"
        "• Cybersource 🌐\n"
        "• Eway 🔄\n"
        "• NMI 🔢\n"
        "• WooCommerce 🛍️\n\n"
        "🛡️ **Security Checks:**\n"
        "• Cloudflare Protection\n"
        "• Captcha Systems\n"
        "• Payment Security Type\n"
        "• CVV Requirements\n\n"
        "🚀 Happy checking!"
    )
    await message.reply(about_text)

@app.on_message(filters.command("chk"))
async def chk_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply("🚫 You need to register first. Please use the /register command.")
        return

    # Extract URLs from the message
    if message.reply_to_message:
        # If replying to a message, extract URLs from that message
        text = message.reply_to_message.text or message.reply_to_message.caption
    else:
        # Otherwise, use the current message
        text = message.text

    # Use regex to find URLs in the text
    urls = re.findall(r'https?://\S+', text)

    if not urls:
        await message.reply("Please provide URLs to check.")
        return

    response = await message.reply("🔍 **Gateway Checker**\n━━━━━━━━━━━━━━")
    results = []

    for url in urls:
        result = await check_gateway(url)
        if "error" in result:
            gateway_info = (
                f"🔍 **Error Checking Gateway** ❌\n"
                f"━━━━━━━━━━━━━━\n"
                f"[❃] **URL:** {url}\n"
                f"[❃] **Error:** {result['error']}\n"
                f"––––––––––––––––––––\n\n"
            )
        else:
            gateway_info = (
                f"🔍 **Gateway Fetched Successfully** ✅\n"
                f"━━━━━━━━━━━━━━\n"
                f"[❃] **URL:** {url}\n"
                f"[❃] **Payment Gateways:** {', '.join(result['gateways']) if result['gateways'] else 'None'}\n"
                f"[❃] **Captcha Detected:** {result['captcha']}\n"
                f"[❃] **Cloudflare Detected:** {result['cloudflare']}\n"
                f"[❃] **Payment Security Type:** {result['payment_security']}\n"
                f"[❃] **CVV/CVC Requirement:** {result['cvv']}\n"
                f"[❃] **Inbuilt Payment System:** {result['inbuilt_payment']}\n"
                f"[❃] **Status Code:** {result['status_code']}\n"
                f"––––––––––––––––––––\n\n"
            )
        
        results.append(gateway_info)
        
        # Update the message with all results processed so far
        full_message = "🔍 **Gateway Checker**\n━━━━━━━━━━━━━━\n\n" + "".join(results)
        
        try:
            await response.edit(full_message)
        except Exception as e:
            # If edit fails due to message length, send a new message
            response = await message.reply(full_message)

@app.on_message(filters.command("txt") & filters.reply)
async def txt_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply("🚫 You need to register first. Please use the /register command.")
        return

    replied_message = message.reply_to_message
    if not replied_message.document or not replied_message.document.file_name.endswith('.txt'):
        await message.reply("Please reply to a .txt file containing URLs.")
        return

    file = await replied_message.download()
    with open(file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    os.remove(file)

    if not urls:
        await message.reply("No valid URLs found in the file.")
        return

    total_urls = len(urls)
    response = await message.reply(f"📊 Found {total_urls} URLs. Starting check...")

    results = {gateway: [] for gateway in GATEWAYS.keys()}
    checked = 0

    async def update_message():
        while checked < total_urls:
            await asyncio.sleep(2)
            remaining = total_urls - checked
            status = (
                "🔍 **MASS CHECKER**\n"
                "━━━━━━━━━━━━━━\n"
                f"📊 **Total:** {total_urls}\n"
                f"✅ **Checked:** {checked}\n"
                f"⏳ **Remaining:** {remaining}\n"
                f"━━━━━━━━━━━━━━\n"
                f"💳 **Stripe:** {len(results['Stripe'])}\n"
                f"🧠 **Braintree:** {len(results['Braintree'])}\n"
                f"💰 **PayPal:** {len(results['PayPal'])}\n"
                f"🛒 **Shopify:** {len(results['Shopify'])}\n"
                f"🔐 **Authorize.net:** {len(results['Authorize.net'])}\n"
                f"◻️ **Square:** {len(results['Square'])}\n"
                f"🌐 **Cybersource:** {len(results['Cybersource'])}\n"
                f"🔄 **Eway:** {len(results['Eway'])}\n"
                f"🔢 **NMI:** {len(results['NMI'])}\n"
                f"🛍️ **WooCommerce:** {len(results['WooCommerce'])}\n"
            )
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

    update_task.cancel()

    # Send final results
    for gateway, urls in results.items():
        if urls:
            result_text = f"🔍 **{gateway} Hits**\n━━━━━━━━━━━━━━\n" + "\n".join(urls)
            try:
                await message.reply(result_text)
            except Exception as e:
                chunks = [urls[i:i + 50] for i in range(0, len(urls), 50)]
                for i, chunk in enumerate(chunks):
                    chunk_text = f"🔍 **{gateway} Hits (Part {i+1})**\n━━━━━━━━━━━━━━\n" + "\n".join(chunk)
                    await message.reply(chunk_text)

    final_status = (
        "✅ **Check completed!**\n"
        "━━━━━━━━━━━━━━\n"
        f"📊 **Total URLs:** {total_urls}\n"
        f"💳 **Stripe:** {len(results['Stripe'])}\n"
        f"🧠 **Braintree:** {len(results['Braintree'])}\n"
        f"💰 **PayPal:** {len(results['PayPal'])}\n"
        f"🛒 **Shopify:** {len(results['Shopify'])}\n"
        f"🔐 **Authorize.net:** {len(results['Authorize.net'])}\n"
        f"◻️ **Square:** {len(results['Square'])}\n"
        f"🌐 **Cybersource:** {len(results['Cybersource'])}\n"
        f"🔄 **Eway:** {len(results['Eway'])}\n"
        f"🔢 **NMI:** {len(results['NMI'])}\n"
        f"🛍️ **WooCommerce:** {len(results['WooCommerce'])}"
    )
    await response.edit(final_status)

# Run the bot
app.run()

