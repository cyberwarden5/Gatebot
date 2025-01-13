import re
import asyncio
from pyrogram import Client, filters
from pyrogram.types import Message
import aiohttp
import os
import warnings
from urllib3.exceptions import InsecureRequestWarning

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

                for gateway, patterns in GATEWAYS.items():
                    if any(re.search(pattern, html) for pattern in patterns):
                        return status_code, gateway
                return status_code, "Not Found"
    except asyncio.TimeoutError:
        return None, "Timeout"
    except Exception as e:
        return None, "Error"

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
        "• /chk - Check gateways for URLs (max 15)\n"
        "• /txt - Check gateways from a text file\n\n"
        "Supported gateways:\n"
        "• Stripe 💳\n"
        "• Braintree 🧠\n"
        "• Shopify 🛒\n"
        "• PayPal 💰\n\n"
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

    if len(urls) > 15:
        await message.reply("Maximum 15 URLs allowed.")
        return

    response = await message.reply("🔍 GATE CHECKER\n___________________")

    for url in urls:
        # Update message with URL being checked
        current_result = f"\n\n🔹 URL: {url}\n➡️ HTTP: \n➡️ GATEWAY: "
        await response.edit(response.text + current_result)

        # Check gateway
        status_code, gateway = await check_gateway(url)

        # Update message with results
        result = (
            f"\n\n🔹 URL: {url}\n"
            f"➡️ HTTP: {status_code or 'N/A'}\n"
            f"➡️ GATEWAY: {gateway}\n"
        )
        await response.edit(response.text.replace(current_result, result))

    # Add completion message
    await response.edit(response.text + "\n\n✅ Check completed!")

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
    response = await message.reply(f"Found {total_urls} URLs. Starting check...")

    results = {gateway: [] for gateway in GATEWAYS.keys()}
    results["Not Found"] = []
    results["Error"] = []

    async def update_message():
        while True:
            await asyncio.sleep(2)
            checked = sum(len(v) for v in results.values())
            remaining = total_urls - checked
            status = (
                "🔍 MASS CHECKER\n"
                "___________________\n"
                f"📊 Total: {total_urls}\n"
                f"✅ Checked: {checked}\n"
                f"⏳ Remaining: {remaining}\n"
                "___________________\n"
            )
            status += "\n".join(f"{'🔹' if v else '◻️'} {k}: {len(v)}" for k, v in results.items())
            try:
                await response.edit(status)
            except Exception:
                # If edit fails (e.g., message rate limit), continue silently
                pass

    update_task = asyncio.create_task(update_message())

    for url in urls:
        _, gateway = await check_gateway(url)
        results[gateway].append(url)

    update_task.cancel()

    # Send final results
    for gateway, urls in results.items():
        if urls:
            result_text = f"🔍 {gateway} Hits\n---------------\n" + "\n".join(urls)
            try:
                await message.reply(result_text)
            except Exception as e:
                # If message is too long, split it
                chunks = [urls[i:i + 50] for i in range(0, len(urls), 50)]
                for i, chunk in enumerate(chunks):
                    chunk_text = f"🔍 {gateway} Hits (Part {i+1})\n---------------\n" + "\n".join(chunk)
                    await message.reply(chunk_text)

    await response.edit(response.text + "\n\n✅ Check completed!")

# Run the bot
app.run()

