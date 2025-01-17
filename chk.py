from pyrogram import filters
from pyrogram.types import Message
import re
from helper import check_gateway
import logging

logger = logging.getLogger(__name__)

async def chk_command(client, message: Message):
    if message.from_user.id not in client.registered_users:
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
            logger.error(f"Error updating message: {str(e)}")
            response = await message.reply(full_message, 
                                        reply_to_message_id=message.id)

