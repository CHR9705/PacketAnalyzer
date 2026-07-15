import discord
import asyncio
from . import config


class AlertBot:
    def __init__(self):
        intents = discord.Intents.default()
        self.client = discord.Client(intents=intents)
        self.loop = None

        @self.client.event
        async def on_ready():
            self.loop = asyncio.get_running_loop()
            print(f"Logged in as {self.client.user}")
            self.on_ready_callback()

    def set_on_ready(self, callback):
        """Lets main.py hook in logic to run once the bot is connected."""
        self.on_ready_callback = callback

    def notify_new_rows(self, rows):
        """Thread-safe entrypoint — safe to call from the watchdog thread."""
        asyncio.run_coroutine_threadsafe(self._alert_users(rows), self.loop)

    def _format_message(self, row):   # 🟢 해당을 수정해서 어떤 메세지가 뜰건지 변경가능
            attack_type = row.get("attack_type", "Unknown")
            extra_fields = [f"{k}: {v}" for k, v in row.items() if k not in ("rowid", "attack_type")]
            extra_text = "\n".join(extra_fields)
            message = f"⚠️ **공격탐지됨**\nType: {attack_type}"
            if extra_text:
                message += f"\n{extra_text}"
            return message

    async def _alert_users(self, rows):   
        for row in rows:                  
            message = self._format_message(row)   
            print(f"ALERT — {message}")
            for user_id in config.RECIPIENT_IDS:
                try:
                    user = await self.client.fetch_user(user_id)
                    await user.send(message)   
                except discord.Forbidden:
                    print(f"Can't DM {user_id} — DMs disabled or no shared server.")
                except discord.NotFound:
                    print(f"User ID {user_id} not found.")
                except discord.HTTPException as e:
                    print(f"Failed to send to {user_id}: {e}")

    def run(self):
        self.client.run(config.TOKEN)