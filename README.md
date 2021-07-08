<div align="center">
	<a href="https://github.com/iamsarvagyaa/AndroidSecNotes"><img src="static/cover.png" alt="Android Security Notes"></a><br/>
</div>
<p align="center">
  <a href="#getting-started">Getting Started?</a> »
  <a href="https://www.buymeacoffee.com/iamsarvagyaa">Buy me a coffee</a> »
  <a href="#contact-me">Wanna Talk?</a></a>
</p>


****

:rocket: ***Android Security Notes? »*** Here, You will find important concepts, resources, hand-crafted and self-curated notes written by a kind-hearted fellow. The main purpose of this project is to serve as a First-Aid to newbies (like me) and intermediate peep who perform android security.

:handshake: ***Wanna contribute? »*** If you see something wrong or incorrectly interpreted then open an issue or send a pull request. We appreciate your contribution and all suggestions/PRs are welcome. You can also ping me on twitter@iamsarvagyaa.

:scroll: ***Things to be done! »*** I started this project from scratch. Steadily, I will update more resources and notes that I've found useful while learning Android Security. The upcoming lineup for this project ...

- [ ] I will add more resources
- [ ] Add conference papers, notes and more
- [ ] Write more blogposts related to android security ...

****

<a name="synopsis"></a>
## :spiral_notepad: Synopsis

- [Getting Started](#getting-started)
- [HackerOne Reports](#h1-reports)
- [BugBounty Writeups](#bugbounty-writeups)
- [CTF Challenge Writeups](#ctf-writeups)
- [Healthy Digests](#healthy-digests)
- [Vulnerable Applications](#vulnapk)

<a name="getting-started"></a>
### [↑](#synopsis) Getting Started

- [Diving in Android Security](https://iamsarvagyaa.github.io/android-security-part-one/)
- [Android Security - Understanding Android Basics](https://payatu.com/blog/amit/Need-to-know-Android)
- [Android Pentesting Lab Setup](https://payatu.com/blog/amit/android_pentesting_lab)
- [Getting started with Frida on Android Apps](https://payatu.com/blog/amit/Getting%20_started_with_Frida)
- [Android Penetration Testing: Apk Reverse Engineering](https://www.hackingarticles.in/android-penetration-testing-apk-reverse-engineering/)
- [Android Penetration Testing: APK Reversing (Part 2)](https://www.hackingarticles.in/android-penetration-testing-apk-reversing-part-2/)

<a name="h1-reports"></a>
### [↑](#synopsis) HackerOne Reports

- Account hijacking possible through ADB backup feature :: [#12617](https://hackerone.com/reports/12617)
- Twitter android app Fragment Injection :: [#43988](https://hackerone.com/reports/43988)
- Bypass Setup by External Activity Invoke :: [#55064](https://hackerone.com/reports/55064)
- Webview Vulnerablity in OwnCloud apk :: [#87835](https://hackerone.com/reports/87835)
- No permission set on Activities [Android App] :: [#145402](https://hackerone.com/reports/145402)
- Flaw in login with twitter to steal Oauth tokens :: [#44492](https://hackerone.com/reports/44492)
- Authentication Failed Mobile version :: [#55530](https://hackerone.com/reports/55530)
- Multiple Stored XSS on Sanbox.veris.in through Veris Frontdesk Android App :: [#121275](https://hackerone.com/reports/121275)
- Coinbase Android Security Vulnerabilities :: [#5786](https://hackerone.com/reports/5786)
- Insecure Data Storage in Vine Android App :: [#44727](https://hackerone.com/reports/44727)
- Sending payments via QR code does not require confirmation :: [#126784](https://hackerone.com/reports/126784)
- Bypass pin(4 digit passcode on your android app) :: [#50884](https://hackerone.com/reports/50884)
- REG: Content provider information leakage :: [#146179](https://hackerone.com/reports/146179)
- Shopify android client all API request's response leakage, including access_token, cookie, response header, response body content :: [#56002](https://hackerone.com/reports/56002)
- HTML/XSS rendered in Android App of Crashlytics through fabric.io :: [#41856](https://hackerone.com/reports/41856)
- ByPassing the email Validation Email on Sign up process in mobile apps :: [#57764](https://hackerone.com/reports/57764)
- Insecure Local Data Storage : Application stores data using a binary sqlite database :: [#57918](https://hackerone.com/reports/57918)
- Vulnerable to JavaScript injection. (WXS) (Javascript injection)! :: [#54631](https://hackerone.com/reports/54631)
- Coinbase Android Application - Bitcoin Wallet Leaks OAuth Response Code :: [#5314](https://hackerone.com/reports/5314)
- Reflected XSS in Zomato Mobile - category parameter :: [#230119](https://hackerone.com/reports/230119)
- MEW Wallet PIN Bypass [Android] :: [#1242212](https://hackerone.com/reports/1242212)
- Firebase Database Takeover in Zego Sense Android app :: [#1065134](https://hackerone.com/reports/1065134)
- Bypass of biometrics security functionality is possible in Android application (com.shopify.mobile) :: [#637194](https://hackerone.com/reports/637194)
- Persistant Arbitrary code execution in mattermost android :: [#1115864](https://hackerone.com/reports/1115864)
- porcupiney.hairs : Java/Android - Insecure Loading of a Dex File :: [#1161956](https://hackerone.com/reports/1161956)
- Unsafe deserialization leads to token leakage in PayPal & PayPal for Business [Android] :: [#453791](https://hackerone.com/reports/453791)
- Cookie steal through content Uri :: [#876192](https://hackerone.com/reports/876192)
- Bypassing Passcode/Device credentials :: [#747726](https://hackerone.com/reports/747726)
- [Java] CWE-755: Query to detect Local Android DoS caused by NFE :: [#1061211](https://hackerone.com/reports/1061211)
- Path traversal in ZIP extract routine on LINE Android :: [#859469](https://hackerone.com/reports/859469)
- Android: Explanation of Access to app protected components vulnerability :: [#951691](https://hackerone.com/reports/951691)
- Java: CWE-749 Unsafe resource loading in Android WebView leaking to injection attacks :: [#1011956](https://hackerone.com/reports/1011956)
- Android WebViews in Twitter app are vulnerable to UXSS due to configuration and CVE-2020-6506 :: [#906433](https://hackerone.com/reports/906433)
- Denial of Service | twitter.com & mobile.twitter.com :: [#903740](https://hackerone.com/reports/903740)
- Insecure Storage and Overly Permissive API Keys in Android App :: [#753868](https://hackerone.com/reports/753868)
- [Grab Android/iOS] Insecure deeplink leads to sensitive information disclosure :: [#401793](https://hackerone.com/reports/401793)
- No session logout after changing password & alsoandroid sessions not shown in sessions list so they can be deleted :: [#194329](https://hackerone.com/reports/194329)
- CVE-2019-5765: 1-click HackerOne account takeover on all Android devices :: [#563870](https://hackerone.com/reports/563870)
- API Keys Hardcoded in Github repository :: [#766346](https://hackerone.com/reports/766346)
- Changing email address on Twitter for Android unsets "Protect your Tweets" :: [#472013](https://hackerone.com/reports/472013)
- Golden techniques to bypass host validations in Android apps :: [#431002](https://hackerone.com/reports/431002)
- Improper protection of FileContentProvider :: [#331302](https://hackerone.com/reports/331302)
- Extremly simple way to bypass Nextcloud-Client PIN/Fingerprint lock :: [#331489](https://hackerone.com/reports/331489)
- Disclosure of all uploads to Cloudinary via hardcoded api secret in Android app :: [#351555](https://hackerone.com/reports/351555)
- [Mail.Ru Android] Typo in permission name allows to write contacts without user knowledge :: [#440749](https://hackerone.com/reports/440749)
- SQL Injection found in NextCloud Android App Content Provider :: [#291764](https://hackerone.com/reports/291764)
- [Android] HTML Injection in BatterySaveArticleRenderer WebView :: [#176065](https://hackerone.com/reports/176065)
- SQLi allow query restriction bypass on exposed FileContentProvider :: [#518669](https://hackerone.com/reports/518669)
- [Zomato Android/iOS] Theft of user session :: [#328486](https://hackerone.com/reports/328486)
- Protected Tweets setting overridden by Android app :: [#519059](https://hackerone.com/reports/519059)
- Bypassing lock protection :: [#490946](https://hackerone.com/reports/490946)
- Improper validation allows user to unlock Zomato Gold multiple times at the same restaurant within one day :: [#486629](https://hackerone.com/reports/486629)
- Authorization bypass using login by phone option+horizontal escalation possible on Grab Android App :: [#205000](https://hackerone.com/reports/205000)
- [IRCCloud Android] XSS in ImageViewerActivity :: [#283063](https://hackerone.com/reports/283063)
- [IRCCloud Android] Theft of arbitrary files leading to token leakage :: [#288955](https://hackerone.com/reports/288955)
- Two-factor authentication bypass on Grab Android App :: [#202425](https://hackerone.com/reports/202425)
- Android - Access of some not exported content providers :: [#272044](https://hackerone.com/reports/272044)
- Improper markup sanitisation in Simplenote Android application :: [#297547](https://hackerone.com/reports/297547)
- [Android] XSS via start ContentActivity :: [#189793](https://hackerone.com/reports/189793)
- [iOS/Android] Address Bar Spoofing Vulnerability :: [#175958](https://hackerone.com/reports/175958)
- Access of Android protected components via embedded intent :: [#200427](https://hackerone.com/reports/200427)
- Possible to steal any protected files on Android :: [#161710](https://hackerone.com/reports/161710)
- [Quora Android] Possible to steal arbitrary files from mobile device :: [#258460](https://hackerone.com/reports/258460)
- Multiple critical vulnerabilities in Odnoklassniki Android application :: [#97295](https://hackerone.com/reports/97295)
- Android - Possible to intercept broadcasts about uploaded files :: [#167481](https://hackerone.com/reports/167481)
- Download attachments with traversal path into any sdcard directory (incomplete fix 106097) :: [#284346](https://hackerone.com/reports/284346)
- [IRCCloud Android] Opening arbitrary URLs/XSS in SAMLAuthActivity :: [#283058](https://hackerone.com/reports/283058)
- Mapbox Android SDK uses Broadcast Receiver instead of Local Broadcast Manager :: [#192886](https://hackerone.com/reports/192886)
- Twitter for android is exposing user's location to any installed android app :: [#185862](https://hackerone.com/reports/185862)
- Vulnerable exported broadcast receiver :: [#289000](https://hackerone.com/reports/289000)
- Android MailRu Email: Thirdparty can access private data files with small user interaction :: [#226191](https://hackerone.com/reports/226191)
- Vine - overwrite account associated with email via android application :: [#187714](https://hackerone.com/reports/187714)
- Activities are not Protected and able to crash app using other app (Can Malware or third parry app) :: [#65729](https://hackerone.com/reports/65729)
- Account takeover intercepting magic link for Arrive app :: [#855618](https://hackerone.com/reports/855618)

<a name="bugbounty-writeups"></a>

### [↑](#synopsis) BugBounty Writeups

- [Brave — Stealing your cookies remotely](https://infosecwriteups.com/brave-stealing-your-cookies-remotely-1e09d1184675)
- [Hack crypto secrets from heap memory to exploit Android application](https://infosecwriteups.com/hack-crypto-secrets-from-heap-memory-to-exploit-android-application-728097fcda3)
- [Guest Blog Post: Firefox for Android LAN-Based Intent Triggering](https://blog.mozilla.org/attack-and-defense/2020/11/10/firefox-for-android-lan-based-intent-triggering/)
- [Arbitrary File Write On Client By ADB Pull](https://daeken.svbtle.com/arbitrary-file-write-by-adb-pull)
- [Vulnerability in Facebook Android app nets $10k bug bounty](https://portswigger.net/daily-swig/vulnerability-in-facebook-android-app-nets-10k-bug-bounty)
- [Universal XSS in Android WebView (CVE-2020-6506)](https://alesandroortiz.com/articles/uxss-android-webview-cve-2020-6506/)
- [How two dead accounts allowed REMOTE CRASH of any Instagram android user](https://www.valbrux.it/blog/2019/09/13/how-two-dead-users-allowed-remote-crash-of-any-instagram-android-user/)
- [Don’t stop at one bug $$$$](https://infosecwriteups.com/dont-stop-at-one-bug-d3c56806b5)
- [Arbitrary code execution on Facebook for Android through download feature](https://medium.com/@dPhoeniixx/arbitrary-code-execution-on-facebook-for-android-through-download-feature-fb6826e33e0f)
- [Ability To Backdoor Facebook For Android](https://ash-king.co.uk/blog/backdoor-android-facebook)
- [From Android Static Analysis to RCE on Prod](https://blog.dixitaditya.com/from-android-app-to-rce/)
- [Smear phishing: a new Android vulnerability](https://jameshfisher.com/2020/08/06/smear-phishing-how-to-scam-an-android-user/)
- [Hunting Android Application Bugs Using Android Studio](https://co0nan.gitbook.io/writeups/#reporting)
- [Android pin bypass with rate limiting](https://balook.medium.com/android-pin-bypass-with-rate-limiting-a3f5dd811715)
- [Global grant uri in Android 8.0-9.0](https://www.vulnano.com/2020/07/global-grant-uri-in-android-80-90-2018.html)
- [From N/A to Resolved For BackBlaze Android App[Hackerone Platform] Bucket Takeove](https://medium.com/@pig.wig45/from-n-a-to-resolved-for-backblaze-android-app-hackerone-platform-bucket-takeover-f817692a590)
- [Xiaomi Android : Harvest private/system files (Updated POC)](https://servicenger.com/blog/mobile/xiaomiharvestprivatefiles/)
- [Indirect UXSS issue on a private Android target app](https://medium.com/@kunal94/indirect-uxss-issues-on-a-private-integrated-browser-219f6b809b6c)
- [Full Account Takeover (Android Application)](https://vbharad.medium.com/full-account-takeover-android-application-78fa922f78c5)
- [NFC Beaming Bypasses Security Controls in Android [CVE-2019-2114]](https://wwws.nightwatchcybersecurity.com/2019/10/24/nfc-beaming-bypasses-security-controls-in-android-cve-2019-2114/)
- [Address bar spoofing in Firefox Lite for Android and the idiocy that followed](https://blog.0x48piraj.com/address-bar-spoofing-in-firefox-lite-for-android-and-the-idiocy-that-followed/)
- [One Bug To Rule Them All: Modern Android Password Managers and FLAG_SECURE Misuse](https://blog.doyensec.com/2019/08/22/modern-password-managers-flag-secure.html)

<a name="ctf-writeups"></a>

### [↑](#synopsis) CTF Challenge Writeups

- [Good old friend - THCon 2021](https://cryptax.github.io/2021/06/14/thcon-goodold.html) - by cryptax
- [draw.per - THCon 2021](https://cryptax.github.io/2021/06/14/thcon.html) - by cryptax
- [Water Color - S4CTF 2021](https://github.com/1GN1tE/CTF_Writeups/tree/main/Writeups/S4CTF_2021/Water%20Color) - by 1gn1te
- [Memedrive - RITSEC CTF 2021](https://klefz.se/2021/04/12/ritsec-ctf-2021-write-up/#memedrive) - by klefz
- [ezpz - darkCON CTF](https://github.com/karma9874/CTF-Writeups/blob/master/DarkCON_CTF/ezpz/ezpz.md) - by karma9874
- [Fire in the Androiddd - darkCON CTF](https://github.com/karma9874/CTF-Writeups/blob/master/DarkCON_CTF/Fire%20in%20the%20Androiddd/Fire_in_the_Androiddd.md) - by karma9874
- [MobaDEX - HackTM CTF Finals 2020](https://pwndiary.com/hacktm-finals-2020-mobadex) - by umutoztunc
- [hehe - PhantomCTF 3.0](https://github.com/FrigidSec/CTFWriteups/tree/master/PhantomCTF/Android/hehe) - by FrigidSec
- [Vault 101 - Hackers Playground 2020](https://saketupadhyay.codes/2020/08/18/sstf-vault-wtireup.html) - by saketupadhyay
- [android - Google Capture The Flag 2020](https://github.com/luker983/google-ctf-2020/tree/master/reversing/android) - by luker983
- [android - Google Capture The Flag 2020](https://sectt.github.io/writeups/GoogleCTF20/android/README) - by s3np41k1r1t0
- [android - Google Capture The Flag 2020](https://github.com/TFNS/writeups/blob/master/2020-08-24-GoogleCTF/android/README.md) - by TFNS
- [android - Google Capture The Flag 2020](https://github.com/NicolaiSoeborg/ctf-writeups/tree/master/2020/Google%20CTF%202020/Android) - by NicolaiSoeborg
- [prehistoric mario - ALLES! CTF 2020](https://github.com/ARESxCyber/Writeups/tree/master/ALLES!%20CTF%202020/prehistoric%20mario) - by ARESxCyber
- [prehistoric mario - ALLES! CTF 2020](https://ashiq.co.za/posts/ALLES-CTF-Prehistoric-Mario-Writeup/) - by ashiq
- [Tamarin - TokyoWesterns CTF 6th 2020](https://github.com/pwning/public-writeup/tree/master/twctf2020/tamarin) - by pwning
- [Tamarin - TokyoWesterns CTF 6th 2020](https://hxp.io/blog/78/TokyoWesterns-CTF-6th-2020-selected-writeups/#Tamarin) - by hxp
- [Tamarin - TokyoWesterns CTF 6th 2020](https://github.com/Hong5489/TrendMicroCTF2020/tree/main/mobile2) - by Hong5489
- [Chasing a lock - RaziCTF 2020](https://github.com/ternary-bits/CTF-Challenges/blob/master/android/razictf2020-chasing-a-lock/WRITEUP.md) - by ternary-bits
- [Chasing a lock - RaziCTF 2020](https://ctftime.org/writeup/24550) - by Londek
- [Chasing a lock - RaziCTF 2020](https://github.com/t3rmin0x/CTF-Writeups/tree/master/Razi%20CTF/Android/Chasing%20A%20Lock) - by t3rmin0x
- [Chasing a lock - RaziCTF 2020](https://blackbeard666.github.io/pwn_exhibit/content/2020_CTF/RaziCTF/android_lock/lock_writeup.html) - by blackbear666
- [CTF Coin - RaziCTF 2020](https://ctftime.org/writeup/24560) - by cthulhu 
- [CTF Coin - RaziCTF 2020](https://github.com/t3rmin0x/CTF-Writeups/tree/master/Razi%20CTF/Android/CTF%20Coin) - by t3rmin0x
- [Friends - RaziCTF 2020](https://ctftime.org/writeup/24559) - by cthulhu
- [Friends - RaziCTF 2020](https://github.com/t3rmin0x/CTF-Writeups/tree/master/Razi%20CTF/Android/Friends) - by t3rmin0x
- [Meeting - RaziCTF 2020](https://github.com/t3rmin0x/CTF-Writeups/tree/master/Razi%20CTF/Android/Meeting) - by t3rmin0x
- [Strong padlock - RaziCTF 2020](https://github.com/t3rmin0x/CTF-Writeups/tree/master/Razi%20CTF/Android/Strong%20Padlock) - by t3rmin0x
- [Strong padlock - RaziCTF 2020](https://ctftime.org/writeup/24500) - by Al3x2
- [Strong padlock - RaziCTF 2020](https://ctftime.org/writeup/24549) - by Londek
- [tough - RaziCTF 2020](https://github.com/t3rmin0x/CTF-Writeups/tree/master/Razi%20CTF/Android/Tough) - by t3rmin0x

<a name="healthy-digests"></a>
### [↑](#synopsis) Healthy Digests

- [Let's Reverse Engineer an Android App!](https://yasoob.me/posts/reverse-engineering-android-apps-apktool/) - Well written blogpost by [M.Yasoob Ullah Khalid](https://github.com/yasoob), which explains how APK reverse engineering generally works.
- [Reverse Engineering Nike Run Club Android App Using Frida](https://yasoob.me/posts/reverse-engineering-nike-run-club-using-frida-android/) - In this blogpost [M.Yasoob Ullah Khalid](https://github.com/yasoob), tell about How we can reverse an android application using Frida.
- [Android Application Security Series](https://manifestsecurity.com/android-application-security/) - Well structured, Android Application Security Series. Start learning from this healthy digest. In this series Aditya covered OWASP MOBILE TOP 10 vulnerabilities in detailed form.
- [Android App Reverse Engineering 101](https://www.ragingrock.com/AndroidAppRE/) - Wanna learn reverse engineering of Android Applications? If yes, then dive into this course. I learned a lot from this, huge thanks to maddiestone.
- [MOBISEC](https://mobisec.reyammer.io/) - Hands-On classes, slides related to mobile security. I recommend everyone to watch all the recordings of class sessions. Kudos [Yanick Fratantonio](https://twitter.com/reyammer) sir, thank you for all the sessions.
- [Oversecured Blog](https://blog.oversecured.com/) - One of the best blog for android security, I love to read all the posts twice in a month. :heart:

<a name="vulnapk"></a>
### [↑](#synopsis) Vulnerable Applications

- [hpAndro](http://ctf.hpandro.raviramesh.info/) - One of the nice vulnerable android application to practice. Plenty of challenges are there, and most of the challenges are beginner friendly. I recommend everyone to checkout this vulnerable application. This challenge is maintained by [hpandro1337](https://twitter.com/hpandro1337), you can also checkout his YouTube Channel : [Android AppSec](https://www.youtube.com/AndroidAppSec).
- [InjuredAndroid](https://github.com/B3nac/InjuredAndroid) - A vulnerable android application ctf examples based on bug bounty findings, exploitation concepts, and pure creativity. Created and maintained by [B3nac](https://twitter.com/B3nac).
- [Oversecured Vulnerable Android App](https://github.com/oversecured/ovaa) - an Android app that aggregates all the platform's known and popular security vulnerabilities. Plenty of vulnerabilities are there to practice our Security skills. Vulnerable Lab maintained by [Bagipro](https://twitter.com/_bagipro).
- [MOBISEC Challenges](https://mobisec.reyammer.io/challs) - Plenty of challenges are there related to Android App development, Reversing of Android Application and Exploitations. Challenges created by sir [Yanick Fratantonio](https://twitter.com/reyammer). This is in my TODO list...

<a name="contact-me"></a>
### Wanna Contact with me?
- LinkedIn  : [iamsarvagyaa](https://www.linkedin.com/in/iamsarvagyaa/)
- Twitter   : [iamsarvagyaa](https://twitter.com/iamsarvagyaa)
- Instagram : [iamsarvagyaa](https://instagram.com/instagram)
- Keybase   : [iamsarvagyaa](https://keybase.io/iamsarvagyaa)
- E-mail    : [iamsarvagyaa@gmail.com](mailto:iamsarvagyaa@gmail.com)

> :mega: If you enjoyed this project and wanna appreciate me, Buy me a cup of coffee. You can also help via sharing this project among the community to help it grow. You may support me on [Buy me a coffee](https://www.buymeacoffee.com/iamsarvagyaa), monetary contributions are always welcome. If you wish to sponsor this project, ping me - iamsarvagyaa[at]gmail.com