import logging
import os
import html
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from telegram import Update
from telegram.ext import (
    Application, CommandHandler, MessageHandler,
    filters, ContextTypes
)
from django.conf import settings

from .serializers import ScanRequestSerializer
from .services.url_analyser import analyse_url
from .services.virustotal import check_virustotal
from .services.whois_check import check_domain_age
from .services.safe_browsing import check_safe_browsing
from .services.gemini_analyser import analyse_with_gemini
from .services.scorer import calculate_risk

logger = logging.getLogger(__name__)

# Reuse a module-level executor to avoid spawning/destroying threads per request
bot_executor = ThreadPoolExecutor(max_workers=16)

# Cached Application instance
_telegram_app = None
_app_lock = asyncio.Lock()


def run_scan(url: str) -> dict:
    url_analysis = analyse_url(url)

    futures = {
        bot_executor.submit(check_virustotal, url): "virustotal",
        bot_executor.submit(check_domain_age, url): "domain_age",
        bot_executor.submit(check_safe_browsing, url): "safe_browsing",
        bot_executor.submit(analyse_with_gemini, url): "gemini",
    }
    results = {}
    for future in as_completed(futures):
        key = futures[future]
        try:
            results[key] = future.result()
        except Exception as e:
            results[key] = {"status": "ERROR", "score": 0, "note": str(e)}

    return calculate_risk(
        url_analysis,
        results.get("virustotal", {}),
        results.get("domain_age", {}),
        results.get("safe_browsing", {}),
        results.get("gemini", {}),
    )


def format_verdict(result: dict) -> str:
    verdict = result["verdict"]
    score = result["risk_score"]
    message = html.escape(result["message"])
    breakdown = result["breakdown"]
    active_flags = result.get("active_flags", [])

    if verdict == "DANGEROUS":
        emoji = "🚨"
        header = "🚨 <b>DANGEROUS LINK DETECTED</b>"
    elif verdict == "SUSPICIOUS":
        emoji = "⚠️"
        header = "⚠️ <b>SUSPICIOUS LINK</b>"
    else:
        emoji = "✅"
        header = "✅ <b>LINK APPEARS SAFE</b>"

    status_emoji = {
        "PASSED": "✅", "FAILED": "❌", "WARNING": "⚠️",
        "SKIPPED": "⏭", "PENDING": "⏳", "ERROR": "❓", "MALICIOUS": "🚫",
    }

    text = f"{header}\n"
    text += f"Risk Score: <b>{score}/100</b>\n\n"
    text += f"{message}\n\n"

    if active_flags:
        text += "<b>What we found:</b>\n"
        for flag in active_flags[:3]:
            text += f"• {html.escape(flag)}\n"
        text += "\n"

    text += "<b>Security Checks:</b>\n"
    checks = [
        ("🔗 URL Structure", breakdown.get("url_structure", {}).get("status", "ERROR")),
        ("🛡 VirusTotal", breakdown.get("virustotal", {}).get("status", "ERROR")),
        ("📅 Domain Age", breakdown.get("domain_age", {}).get("status", "ERROR")),
        ("🔍 Safe Browsing", breakdown.get("safe_browsing", {}).get("status", "ERROR")),
        ("🤖 Gemini AI", breakdown.get("gemini_ai", {}).get("status", "ERROR")),
    ]

    for check_name, check_status in checks:
        s_emoji = status_emoji.get(check_status, "❓")
        text += f"{check_name}: {s_emoji}\n"

    text += f"\n<i>Powered by ShieldAI · CipherLabs</i>"
    return text


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Welcome to <b>ShieldAI PhishGuard</b>\n\n"
        "I protect Nigerians from phishing links and online fraud.\n\n"
        "<b>How to use:</b>\n"
        "Send me any suspicious link and I will analyse it instantly "
        "across 5 security checks.\n\n"
        "<b>Example:</b>\n"
        "<code>https://gtb4nk-verify.xyz</code>\n\n"
        "I will tell you if it is:\n"
        "✅ Safe\n"
        "⚠️ Suspicious\n"
        "🚨 Dangerous\n\n"
        "<i>Powered by ShieldAI · CipherLabs</i>",
        parse_mode="HTML"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "<b>ShieldAI PhishGuard Help</b>\n\n"
        "Simply send any URL and I will scan it.\n\n"
        "<b>What I check:</b>\n"
        "• URL structure analysis\n"
        "• VirusTotal — 70+ security vendors\n"
        "• Domain age verification\n"
        "• Google Safe Browsing database\n"
        "• Gemini AI impersonation detection\n\n"
        "<b>Commands:</b>\n"
        "/start — Welcome message\n"
        "/help — This message\n"
        "/about — About ShieldAI\n\n"
        "<i>Powered by ShieldAI · CipherLabs</i>",
        parse_mode="HTML"
    )


async def about_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "<b>About ShieldAI</b>\n\n"
        "ShieldAI is Nigeria's first intelligent two-layer fraud prevention platform.\n\n"
        "<b>PhishGuard</b> detects scam links before you click them.\n"
        "<b>BehaviorID</b> blocks attackers even when they have your password.\n\n"
        "Built by *CipherLabs* for the OPay Innovation Challenge 2026.\n\n"
        "🌐 Web App: your-railway-url.up.railway.app\n\n"
        "<i>Detect. Authenticate. Defend.</i>",
        parse_mode="HTML"
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return

    text = update.message.text.strip()

    # Check if it looks like a URL
    if text.startswith("http://") or text.startswith("https://"):
        # Send scanning message first
        scanning_msg = await update.message.reply_text(
            "🔍 Scanning link across 5 security checks...\n"
            "This usually takes 2-3 seconds.",
        )

        try:
            serializer = ScanRequestSerializer(data={"url": text})
            if not serializer.is_valid():
                await scanning_msg.edit_text(
                    "⚠️ That doesn't look like a valid URL.\n\n"
                    "Please send a complete link starting with http:// or https://"
                )
                return

            # Run scan
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, run_scan, text)

            verdict_text = format_verdict(result)

            await scanning_msg.edit_text(verdict_text, parse_mode="HTML")

        except Exception as e:
            logger.exception("Error scanning URL in telegram bot")
            await scanning_msg.edit_text(
                "❌ Something went wrong while scanning.\n\n"
                "Please try again or visit our web app."
            )
    else:
        await update.message.reply_text(
            "Please send a URL to scan.\n\n"
            "Example: <code>https://suspicious-link.com</code>\n\n"
            "Type /help for more information.",
            parse_mode="HTML"
        )


async def get_telegram_app():
    global _telegram_app
    if _telegram_app is not None:
        return _telegram_app

    async with _app_lock:
        if _telegram_app is not None:
            return _telegram_app

        token = settings.TELEGRAM_BOT_TOKEN
        if not token:
            return None

        app = Application.builder().token(token).build()
        app.add_handler(CommandHandler("start", start_command))
        app.add_handler(CommandHandler("help", help_command))
        app.add_handler(CommandHandler("about", about_command))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        
        await app.initialize()
        await app.start()
        _telegram_app = app
        return _telegram_app