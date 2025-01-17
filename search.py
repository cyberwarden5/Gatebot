from pyrogram import filters
from pyrogram.types import Message
from googlesearch import search
import os
import logging

logger = logging.getLogger(__name__)

async def search_command(client, message: Message):
    if message.from_user.id not in client.registered_users:
        await message.reply(
            "🚫 You need to register first. Please use the /register command.", 
            reply_to_message_id=message.id
        )
        return

    try:
        # Parse command arguments
        args = message.text.split(None, 2)
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
        amount = 10  # Default number of results

        if len(args) == 3:
            try:
                amount = int(args[2])
                if amount < 1:
                    amount = 10
            except ValueError:
                amount = 10

        # Send initial status message
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

        # Process and send results
        if amount <= 10:
            # Directly display results if the number is manageable
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
            # If results exceed 10, save to a file
            file_name = f"search_results_{message.from_user.id}.txt"
            with open(file_name, "w") as f:
                for url in urls:
                    f.write(f"{url}\n")

            # Send the file as a document
            await message.reply_document(
                document=file_name,
                caption=(
                    f"🔍 **Search Results**\n"
                    f"━━━━━━━━━━━━━━━━━━━━\n"
                    f"🔎 **Query:** `{query}`\n"
                    f"📊 **Found:** `{len(urls)}` URLs\n"
                    f"━━━━━━━━━━━━━━━━━━━━"
                ),
                reply_to_message_id=message.id
            )

            # Delete the temporary file
            os.remove(file_name)

            # Delete the status message
            await status_msg.delete()

    except Exception as e:
        logger.error(f"Error in search command: {str(e)}")
        await message.reply(
            f"❌ **Error:**\n`{str(e)}`",
            reply_to_message_id=message.id
        )
