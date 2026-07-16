import discord
import asyncio
from . import config
from datetime import datetime
from zoneinfo import ZoneInfo


def _format_timestamp(value):
        """유닉스 타임스탬프(숫자) 또는 문자열 둘 다 사람이 읽기 좋은 형태로 변환"""
        if value is None:
            return "N/A"
        try:
            # 숫자(유닉스 타임스탬프)인 경우
            dt = datetime.fromtimestamp(float(value))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            # 이미 문자열(예: ISO 포맷)인 경우 그대로 반환
            return str(value)
    
def _build_embed(row):
    attack_type = row.get("attack_type", "Unknown")
    src_ip = row.get("src_ip", "N/A")
    counter = row.get("counter", "N/A")
    first_ts = _format_timestamp(row.get("first_timestamp"))
    last_ts = _format_timestamp(row.get("last_timestamp"))

    embed = discord.Embed(
        title="🚨 공격 탐지됨",
        color=discord.Color.red(),
        timestamp=datetime.now(ZoneInfo("Asia/Seoul"))
    )
    embed.add_field(name="공격 유형", value=f"`{attack_type}`", inline=False)
    embed.add_field(name="Source IP", value=f"`{src_ip}`", inline=True)
    embed.add_field(name="First Seen", value=first_ts, inline=True)
    embed.add_field(name="Last Seen", value=last_ts, inline=True)
    embed.add_field(name="횟수", value=f"`{counter}`", inline=True)
    embed.set_footer(text=f"ID: {row.get('id', 'N/A')}")

    return embed

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
    
    


    async def _alert_users(self, rows):
        for row in rows:
            embed = _build_embed(row)
            print(f"ALERT — {row.get('attack_type')} from {row.get('src_ip')}")
            for user_id in config.RECIPIENT_IDS:
                try:
                    user = await self.client.fetch_user(user_id)
                    await user.send(embed=embed)   
                except discord.Forbidden:
                    print(f"해당 유저 {user_id}는 등록되어있지 않습니다. ")
                except discord.NotFound:
                    print(f"해당 유저 : {user_id} 없음")
                except discord.HTTPException as e:
                    print(f"전송 실패! 대상유저: {user_id}: {e}")

    def run(self):
        self.client.run(config.TOKEN)