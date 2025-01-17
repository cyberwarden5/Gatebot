import logging
from pyrogram import Client, filters
from pyrogram.types import Message
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Bot configuration
API_ID = os.getenv("API_ID")
API_HASH = os.getenv("API_HASH")
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = int(os.getenv("ADMIN_ID"))

# Initialize the bot
app = Client("gateway_checker_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# Store registered users
registered_users = set()

# Import command handlers
from search import search_command
from txt import txt_command
from chk import chk_command

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

# Register command handlers
app.add_handler(filters.command("search"), search_command)
app.add_handler(filters.command("txt"), txt_command)
app.add_handler(filters.command("chk"), chk_command)

if __name__ == "__main__":
    logger.info("🚀 Starting Gateway Checker Bot...")
    app.run()

