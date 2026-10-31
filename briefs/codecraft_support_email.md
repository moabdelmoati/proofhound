Subject: All API models returning 503 "service_upgrading" for over an hour

Hi CodeCraft team,

Every request to the chat completions endpoint has been failing for more than an
hour with a 503 error, regardless of which model I select:

    POST https://codecraftapi.com/v1/chat/completions
    -> HTTP 503
    {"error":{"code":"service_upgrading",
              "message":"Our service is being upgraded right now and will be back
                         to normal within a few minutes. Please retry."}}

I have confirmed this happens on all models I tried — claude-sonnet-5,
claude-opus-5.5, gpt-5.5, gemini-3.1-pro, deepseek-v4, grok-4.5 — so it looks
service-wide, not model-specific.

My account/key itself is fine:
- GET /v1/models returns 200 and lists all models correctly.
- There is no billing error (no 402) — I topped up and the balance is valid.

The message says "a few minutes" but it has now been well over an hour. Could you
please let me know:
1. Is there an outage or an ETA for when the service will be back to normal?
2. Is there anything I need to do on my side?

I have time-sensitive evaluation runs blocked on this. Any update would be
appreciated. Thank you.
