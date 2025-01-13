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
    try:
        async with aiohttp.ClientSession() as session:
            # Ignore SSL verification
            async with session.get(url, ssl=False, timeout=10) as response:
                html = await response.text()
                status_code = response.status

                soup = BeautifulSoup(html, 'html.parser')

                gateways_found = []
                for gateway, patterns in GATEWAYS.items():
                    if any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns):
                        gateways_found.append(gateway)

                captcha_detected = "Yes" if re.search(r"captcha|recaptcha|hcaptcha", html, re.IGNORECASE) else "No"
                cloudflare_detected = "Yes" if "cloudflare" in html.lower() or "__cf_" in html else "No"
                payment_security = "3D" if "3d-secure" in html.lower() or "three-d-secure" in html.lower() else "2D"
                cvv_required = "Required" if re.search(r"cvv|cvc|security code", html, re.IGNORECASE) else "Not Required"
                inbuilt_payment = "Yes" if re.search(r"checkout|payment", html, re.IGNORECASE) else "No"

                # Advanced detection for Cloudflare and reCAPTCHA
                if cloudflare_detected == "No":
                    cloudflare_detected = "Yes" if soup.find('a', href=re.compile(r'cloudflare.com')) else "No"

                if captcha_detected == "No":
                    captcha_detected = "Yes" if soup.find('div', class_=re.compile(r'g-recaptcha|h-captcha')) else "No"

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
    except Exception as e:
        return {"error": str(e)}

@app.on_message(filters.command("start"))
async def start_command(client, message: Message):
    user_id = message.from_user.id
    if user_id not in registered_users:
        await message.reply("🚫 You need to register first. Please use the /register command.")
    else:
        await message.reply("👋 Welcome back! Use /about to learn more about the bot.")

@app.on_message(filters.command("register"))
async def register_command(client, message: Message):
    user_id = message.from_user.id
    if user_id not in registered_users:
        registered_users.add(user_id)
        user_info = f"New user registered:\nName: {message.from_user.first_name}\nUsername: @{message.from_user.username}\nID: {user_id}"
        await client.send_message(ADMIN_ID, user_info)
        await message.reply("✅ Registration successful! You can now use the bot.")
    else:
        await message.reply("You're already registered!")

@app.on_message(filters.command("about"))
async def about_command(client, message: Message):
    about_text = (
        "🔍 **Gateway Checker Bot**\n\n"
        "This bot helps you check payment gateways for URLs.\n\n"
        "Available commands:\n"
        "• /chk - Check gateways for multiple URLs\n"
        "• /txt - Check gateways from a text file\n\n"
        "Supported gateways:\n"
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
        "Happy checking! 🚀"
    )
    await message.reply(about_text)

@app.on_message(filters.command("chk"))
async def chk_command(client, message: Message):
    if message.from_user.id not in registered_users:
        await message.reply("🚫 You need to register first. Please use the /register command.")
        return

    urls = message.text.split("\n")[1:]
    if not urls:
        await message.reply("Please provide URLs to check.")
        return

    response = await message.reply("🔍 Gateway Checker\n━━━━━━━━━━━━━━")

    for url in urls:
        result = await check_gateway(url)
        if "error" in result:
            gateway_info = f"🔍 Error: {result['error']} ❌\n"
        else:
            gateway_info = (
                f"🔍 Gateway Fetched Successfully ✅\n"
                f"━━━━━━━━━━━━━━\n"
                f"[❃] URL: {url}\n"
                f"[❃] Payment Gateways: {', '.join(result['gateways']) if result['gateways'] else 'None'}\n"
                f"[❃] Captcha Detected: {result['captcha']}\n"
                f"[❃] Cloudflare Detected: {result['cloudflare']}\n"
                f"[❃] Payment Security Type: {result['payment_security']}\n"
                f"[❃] CVV/CVC Requirement: {result['cvv']}\n"
                f"[❃] Inbuilt Payment System: {result['inbuilt_payment']}\n"
                f"[❃] Status Code: {result['status_code']}\n"
                f"––––––––––––––––––––\n\n"
            )

        try:
            await response.edit(response.text + gateway_info)
        except Exception:
            # If edit fails, send a new message
            response = await message.reply(response.text + gateway_info)

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
                "🔍 MASS CHECKER\n"
                "━━━━━━━━━━━━━━\n"
                f"📊 Total: {total_urls}\n"
                f"✅ Checked: {checked}\n"
                f"⏳ Remaining: {remaining}\n"
                f"━━━━━━━━━━━━━━\n"
                f"💳 Stripe: {len(results['Stripe'])}\n"
                f"🧠 Braintree: {len(results['Braintree'])}\n"
                f"💰 PayPal: {len(results['PayPal'])}\n"
                f"🛒 Shopify: {len(results['Shopify'])}\n"
                f"🔐 Authorize.net: {len(results['Authorize.net'])}\n"
                f"◻️ Square: {len(results['Square'])}\n"
                f"🌐 Cybersource: {len(results['Cybersource'])}\n"
                f"🔄 Eway: {len(results['Eway'])}\n"
                f"🔢 NMI: {len(results['NMI'])}\n"
                f"🛍️ WooCommerce: {len(results['WooCommerce'])}\n"
            )
            try:
                await response.edit(status)
            except Exception:
                # If edit fails, continue silently
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
            result_text = f"🔍 {gateway} Hits\n━━━━━━━━━━━━━━\n" + "\n".join(urls)
            try:
                await message.reply(result_text)
            except Exception as e:
                # If message is too long, split it
                chunks = [urls[i:i + 50] for i in range(0, len(urls), 50)]
                for i, chunk in enumerate(chunks):
                    chunk_text = f"🔍 {gateway} Hits (Part {i+1})\n━━━━━━━━━━━━━━\n" + "\n".join(chunk)
                    await message.reply(chunk_text)

    final_status = (
        "✅ Check completed!\n"
        "━━━━━━━━━━━━━━\n"
        f"📊 Total URLs: {total_urls}\n"
        f"💳 Stripe: {len(results['Stripe'])}\n"
        f"🧠 Braintree: {len(results['Braintree'])}\n"
        f"💰 PayPal: {len(results['PayPal'])}\n"
        f"🛒 Shopify: {len(results['Shopify'])}\n"
        f"🔐 Authorize.net: {len(results['Authorize.net'])}\n"
        f"◻️ Square: {len(results['Square'])}\n"
        f"🌐 Cybersource: {len(results['Cybersource'])}\n"
        f"🔄 Eway: {len(results['Eway'])}\n"
        f"🔢 NMI: {len(results['NMI'])}\n"
        f"🛍️ WooCommerce: {len(results['WooCommerce'])}"
    )
    await response.edit(final_status)

# Run the bot
app.run()

