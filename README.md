This is a proof of concept project to securely handle emailing data and information and use local generative AI to send replies.
As a proof of concept, this project will not be likely to receive further changes or updates.

This tool integrates with both Gmail API and a locally running AI to fettch unread email threads from the inbox, write replies through the AI, and automatically send them replying to the email thread.
It is configured to reply as a support agent and answer queries it receives in the inbox, taking into account the entire email chain if it receives them in a thread. The behavior and purpose of the AI can be easily modified.

To use this tool, it is necessary to configure the Gmail account through [Google Cloud Console](https://console.cloud.google.com/) and obtain the required OAuth key for the Gmail account.
Additionally, it is configured to integrate with [Oogabooga's Text Generation Web UI](https://github.com/oobabooga/text-generation-webui), but can be easily reconfigured to connect with OpenAI's ChatGPT API (which would defeat the purpose of handling email data securely and with confidentiality)
