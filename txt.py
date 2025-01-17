from pyrogram import filters
from pyrogram.types import Message
import os
import asyncio
from helper import check_gateway
import logging

logger = logging.getLogger(__name__)

async def txt_command(client, message: Message):
    if message.from_user.id not in client.registered_users:
        await message.reply("🚫 You need to register first. Please use the /register command.", 
                            reply_to_message_id=message.id)
        return

    replied_message = message.reply_to_message
    if not replied_message or not replied_message.document or not replied_message.document.file_name.endswith('.txt'):
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
