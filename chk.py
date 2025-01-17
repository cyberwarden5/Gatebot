import logging
import re
from pyrogram import filters
from pyrogram.types import Message
from helper import check_gateway

logger = logging.getLogger(__name__)

async def chk_command(client, message: Message):
    # Ensure the user is registered
    if message.from_user.id not in client.registered_users:
        await message.reply(
            "🚫 You need to register first. Please use the /register command.",
            reply_to_message_id=message.id
        )
        return

    # Extract text from the message or a reply
    text = message.reply_to_message.text if message.reply_to_message else message.text

    if not text:
        await message.reply(
            "❌ No text found to extract URLs. Please provide URLs to check.",
            reply_to_message_id=message.id
        )
        return

    # Use regex to find URLs in the provided text
    urls = re.findall(r'https?://\S+', text)
    
    if not urls:
        await message.reply(
            "❌ No valid URLs found. Please provide URLs in the message.",
            reply_to_message_id=message.id
        )
        return

    if len(urls) > 15:
        await message.reply(
            "❌ Maximum 15 URLs are allowed. Please provide fewer URLs.",
            reply_to_message_id=message.id
        )
        return

    # Notify the user that the gateway check has started
    response = await message.reply(
        "🔍 **Gateway Checker**\n"
        "━━━━━━━━━━━━━━\n"
        "Processing your URLs, please wait...",
        reply_to_message_id=message.id
    )

    results = []

    # Loop through each URL and process it
    for url in urls:
        try:
            result = await check_gateway(url)
            if "error" in result:
                gateway_info = (
                    f"❌ **Error Checking Gateway**\n"
                    f"━━━━━━━━━━━━━━\n"
                    f"➜ **URL:** `{url}`\n"
                    f"➜ **Error:** `{result['error']}`\n"
                    "━━━━━━━━━━━━━━\n\n"
                )
            else:
                gateway_info = (
                    f"✅ **Gateway Fetched Successfully**\n"
                    f"━━━━━━━━━━━━━━\n"
                    f"➜ **URL:** `{url}`\n"
                    f"➜ **Payment Gateways:** {', '.join(result['gateways']) if result['gateways'] else 'None'}\n"
                    f"➜ **Captcha Detected:** {'⚠️ Yes' if result['captcha']['detected'] else 'No'}\n"
                    f"➜ **Captcha Types:** {', '.join(result['captcha']['types']) if result['captcha']['detected'] else 'N/A'}\n"
                    f"➜ **Cloudflare Protection:** {'⚡ Yes' if result['cloudflare'] else 'No'}\n"
                    f"➜ **Payment Security:** {', '.join(result['payment_security']) if result['payment_security'] else 'None detected'}\n"
                    f"➜ **Status Code:** {result['status_code']}\n"
                    "━━━━━━━━━━━━━━\n\n"
                )
            results.append(gateway_info)
        except Exception as e:
            logger.error(f"Error processing URL {url}: {str(e)}")
            results.append(
                f"❌ **Error Checking Gateway**\n"
                f"━━━━━━━━━━━━━━\n"
                f"➜ **URL:** `{url}`\n"
                f"➜ **Error:** `{str(e)}`\n"
                "━━━━━━━━━━━━━━\n\n"
            )

    # Combine all results and send the final response
    full_message = (
        "🔍 **Gateway Checker Results**\n"
        "━━━━━━━━━━━━━━\n\n" + "".join(results)
    )

    try:
        await response.edit(full_message)
    except Exception as e:
        logger.error(f"Error editing the response message: {str(e)}")
        # If the message is too long, split and send as multiple messages
        for chunk in [results[i:i + 5] for i in range(0, len(results), 5)]:
            await message.reply("".join(chunk), reply_to_message_id=message.id)
