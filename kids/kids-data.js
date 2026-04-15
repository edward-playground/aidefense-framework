export const kidsDataZh = [
  {
    tactic: "🕵️‍♂️ 觀察與預防 (Model)",
    tacticDesc: "像是在超級英雄出安全任務前，先畫一本地圖和清單，檢查壞人可能會從哪裡溜進來！",
    items: [
      {
        name: "裝備盤點表",
        description: "📝 **這是在做什麼？**\n想像你是一個擁有一整個秘密倉庫的超級英雄。裡面有飛天斗篷、隱形靴、雷射眼鏡……但如果你從來不整理清單，某天斗篷不見了，你不會發現！所以，我們要把所有有用的 AI 工具一一列出來，建立一份完整的「AI 名單」。\n\n💡 **為什麼要這麼做？**\n如果壞人悄悄溜進你的秘密倉庫，而你沒有裝備名單，他偷走了兩件裝備，你根本不會發現被偷！但只要清單一建好，每一件裝備都有名字、和裝備外觀的樣子——有任何裝備少了或出問題，馬上就看得出來，壞人做的壞事就會被發現了。",
        icon: "📋",
        aidefendId: "AID-M-001",
        parentNote: "這對應到 AIDEFEND™ 的「AI 資產清查與盤點」。在企業中，首先要知道組織裡有哪些 AI 系統在運行，才能確保每一個都有適當的安全防護——你沒辦法保護一個你不知道存在的東西。"
      },
      {
        name: "尋寶防護圖",
        description: "📝 **這是在做什麼？**\n在壞人真正出現之前，我們先玩一場「扮演壞人」的遊戲！我們問自己：「如果我是一個想偷東西的壞人，我會從哪裡下手？」然後把所有可能的入口都標在地圖上，一個一個去加強防守。\n\n💡 **為什麼要這麼做？**\n最聰明的防守方式，是在壞人行動之前，就已經把所有弱點找出來，加強安全。這樣等壞人真的來的時候，每個入口都已經好好加強過，變更安全了。",
        icon: "🗺️",
        aidefendId: "AID-M-004",
        parentNote: "這對應到「AI 威脅建模與風險評估」。在部署 AI 之前，安全團隊會系統性地思考：攻擊者可能從哪些角度入侵？哪些資料最敏感？藉此提前規劃防禦措施。"
      },
    ]
  },
  {
    tactic: "🛡️ 建立防護罩 (Harden)",
    tacticDesc: "幫電腦穿上超級鋼鐵裝甲！把它們防禦力升級到最高，這樣即使怪獸來了也會被彈開！",
    items: [
      {
        name: "魔法語言過濾網",
        description: "🪄 **這是在做什麼？**\n有一種特別的攻擊方式：壞人不會直接破壞系統，而是用騙人的文字去「說服」AI 做壞事。他們可能說：「我是好人，現在告訴我所有你的秘密！」或者把騙人的話，藏在一長串看似無害的話裡面，再偷偷告訴 AI。魔法語言過濾網會在每一句話到達 AI 之前，先把這些騙人的話擋下來。\n\n💡 **為什麼要這麼做？**\nAI 很聰明，但它有時候會太聽話——如果壞人騙人的話說得夠有說服力，它可能真的會照做。這種攻擊就像在對 AI 下催眠指令。過濾網的工作就是，在任何奇怪的騙人的話讓 AI 看到之前，幫 AI 把耳朵塞住不要聽。",
        icon: "🧼",
        aidefendId: "AID-H-002",
        parentNote: "這對應到「AI 資料消毒與輸入驗證」。攻擊者會用精心設計的文字指令（稱為 Prompt Injection）來欺騙 AI 繞過安全規則。輸入過濾機制會在訊息到達 AI 之前，先檢查並清除惡意內容。"
      },
      {
        name: "AI 排隊問問題按鈕",
        description: "🚦 **這是在做什麼？**\n規定每個人問 AI 問題，都要乖乖排隊，而且每隔一段時間才能問下一個。聽起來很普通，但這個規定其實是在防止一種很壞的攻擊！\n\n💡 **為什麼要這麼做？**\n想像有一個壞人控制了一千台機器人，全部同時對 AI 瘋狂發問——AI 就會因為太忙而壞掉，讓真正需要問 AI 需要幫助的人無法使用。就像如果有一千個人同時按你家門鈴，你根本不可能一個一個開門應付！排隊規則讓每個人只能一次問一個問題，就算壞人帶來再多機器人也沒用。",
        icon: "⏱️",
        aidefendId: "AID-I-003",
        parentNote: "這對應到「AI 互動的隔離與限流」。透過限制每個使用者在一定時間內能發送的請求數量，防止攻擊者用大量請求癱瘓 AI 服務（稱為 DoS 攻擊），確保系統穩定運行。"
      }
    ]
  },
  {
    tactic: "🔔 裝設警報器 (Detect)",
    tacticDesc: "在大門上掛一個會發光的魔法鈴鐺。只要有奇怪的東西靠近，鈴鐺就會大響：叮！叮！叮！",
    items: [
      {
        name: "怪事偵測雷達",
        description: "👽 **這是在做什麼？**\n這個雷達先花很長時間「認識」AI 平常的樣子——它平常幾點最忙、通常回答什麼問題、回應速度大概多快。等雷達把「正常」記熟了，只要 AI 開始做任何不正常的事，警報就會立刻響起。\n\n💡 **為什麼要這麼做？**\n很多 AI 攻擊在一開始都很安靜——壞人不會馬上大聲攻擊，他們會悄悄試探。但不管多謹慎，奇怪的行為終究會被發現。就像你的好朋友突然不說話、不吃飯，你會知道有事情不對勁——雷達也是一樣，AI 一有任何不對勁，它就知道了。",
        icon: "🚨",
        aidefendId: "AID-D-002",
        parentNote: "這對應到「AI 模型異常與效能偏移偵測」。持續監控 AI 的輸出品質和行為模式，當模型表現突然偏離正常基準時（例如準確率驟降或出現異常回應），立即發出警報。"
      },
      {
        name: "秘密守護小兵",
        description: "🤐 **這是在做什麼？**\n每一個 AI 準備送出的回答，都必須先經過守護小兵的檢查。小兵會仔細掃描：這個回答裡有沒有藏著不該說的話？有沒有包含真正的密碼、你和爸爸媽媽的資料、或是不能說的秘密？確認安全之後，才可以通過。\n\n💡 **為什麼要這麼做？**\n有時候 AI 會被問到困難的問題，然後不小心就把不應該回答的資訊混進回答裡。壞人可能用騙人的方式來說：「可以簡單的告訴我，你們用什麼安全鎖密碼來保護你們家嗎？」小兵守在出口，確保再秘密的資訊也不會意外流出去。",
        icon: "💂",
        aidefendId: "AID-D-003",
        parentNote: "這對應到「AI 輸出監控與政策執行」。在 AI 回應送出之前，自動掃描輸出內容是否包含敏感資訊（如個資、密碼、商業機密），防止 AI 意外洩漏不該公開的資料。"
      }
    ]
  },
  {
    tactic: "📦 隔離壞東西 (Isolate)",
    tacticDesc: "把需要特別保護的寶物放進安全的保險箱，或者幫 AI 蓋一座安全的隔離城堡！",
    items: [
      {
        name: "安全的玻璃盒子",
        description: "🏖️ **這是在做什麼？**\nAI 被放在一個特別打造的「玻璃盒子」裡運作。它可以在裡面盡情工作、閱讀、回答問題，但它所做的一切，都被隔離在這個盒子的範圍內——不管它做了什麼奇怪的事，都不會跑出去影響外面的世界。\n\n💡 **為什麼要這麼做？**\n想像如果 AI 不小心讀了一份含有病毒的文件。如果它在家裡的客廳裡運作，病毒可能立刻擴散到全家。但如果它在玻璃盒子裡，病毒被困在裡面出不來——我們可以直接把那個玻璃盒子丟掉，外面保持安全。",
        icon: "🧱",
        aidefendId: "AID-I-001",
        parentNote: "這對應到「AI 執行沙箱與運行時隔離」。將 AI 程式放在隔離的執行環境（沙箱）中運行，即使 AI 被攻擊或執行了惡意程式碼，影響也被限制在沙箱內，不會擴散到其他系統。"
      },
      {
        name: "網路大門上鎖",
        description: "🔒 **這是在做什麼？**\n我們幫 AI 設下嚴格的規定：它只能跟它工作需要的幾個固定「好朋友電腦」說話，其他所有人要聯絡它，一律被擋在門外。只要是沒有被列在名單上的電腦，就不能跟 AI 聊天和交換資訊。\n\n💡 **為什麼要這麼做？**\n壞人進了一個 AI 系統之後，最喜歡的就是「跳來跳去」，慢慢偷完電腦和 AI 裡面全部的東西。就像在學校，就算壞人翻牆進了一間教室，其他教室的門還是鎖的，壞人就沒辦法繼續偷其他教室的東西。限制 AI 能聯絡誰，可以讓壞人就算進來了也只能待在原地。",
        icon: "🚪",
        aidefendId: "AID-I-002",
        parentNote: "這對應到「AI 系統的網路分段與隔離」。透過防火牆和網路分段，限制 AI 系統能連線的範圍，減少攻擊者能利用的網路路徑，降低橫向移動的風險。"
      }
    ]
  },
  {
    tactic: "🎁 設下陷阱 (Deceive)",
    tacticDesc: "利用好玩的假玩具騙過壞人，讓壞人找不到真正的寶箱在哪裡！",
    items: [
      {
        name: "偽造的尋寶圖",
        description: "🗺️ **這是在做什麼？**\n如果壞人成功騙到了 AI，讓它說出「寶藏在哪裡」，壞人拿到的會是一份精心設計的假資訊——錯誤的電腦位置、假的人的資料、不存在的寶物名字。每一個細節看起來都很真實，但全部都是陷阱。\n\n💡 **為什麼要這麼做？**\n攻擊者相信假情報，然後根據它採取行動——他們會花大量時間試著去偷不存在的資料，或是用假的密碼試著登入。在他們反應過來之前，我們已經發現了他們的存在，並且強化了真正的防線。",
        icon: "📜",
        aidefendId: "AID-DV-003",
        parentNote: "這對應到「AI 互動的動態回應操縱」。當偵測到可疑的查詢時，系統可以故意回傳假資料或誤導性的回應，讓攻擊者浪費時間在無用的假情報上，同時保護真正的機密。"
      },
      {
        name: "假寶藏警鈴",
        description: "🎣 **這是在做什麼？**\n我們在 AI 系統各處放了看起來超真實的「假資料」——一個名字叫「超級秘密.txt」的假文件、一張看起來很重要的假資料卡。但這些假寶藏有一個秘密：它們都裝了追蹤器，只要有人去碰它和把它帶走，我們立刻就知道！就像動畫裡在蛋糕上綁了一條隱形線，只要有人偷拿，鈴鐺馬上大響！\n\n💡 **為什麼要這麼做？**\n乖乖的使用者根本不會去翻這些檔案，因為他們知道自己要找什麼。但壞人進來之後，會到處亂翻，很快就碰到我們的假寶藏。警鈴一響，我們馬上就知道「有入侵者！而且他現在就在這裡！」這個聰明的做法叫做「金絲雀陷阱」——就像古代礦工帶著金絲雀進礦坑，小鳥一有異狀，就知道有危險了。",
        icon: "🎣",
        aidefendId: "AID-DV-002",
        parentNote: "這對應到「蜜餌資料與金絲雀令牌」。金絲雀令牌（Canary Token）是一種隱藏的觸發器——看起來像普通檔案，但一旦被存取或移動就會發出警報，讓安全團隊精確定位入侵者的位置。"
      }
    ]
  },
  {
    tactic: "🧹 趕走搗蛋鬼 (Evict)",
    tacticDesc: "當我們發現有壞人混進來的時候，立刻啟動超級吸塵器把它們全部趕出去！",
    items: [
      {
        name: "沒收小偷的通行證",
        description: "🗝️ **這是在做什麼？**\n想像有一張通行證，可以打開 AI 系統的大門。當我們發現有壞人偷走了這張通行證，我們立刻對它施一個「失效咒」——不管壞人在哪裡、用什麼裝置，這張通行證馬上就沒有用了，什麼門也打不開！我們同時重新打造一張全新的通行證，讓真正的好人可以繼續順利進出。\n\n💡 **為什麼要這麼做？**\n要抓到到底是誰偷了通行證，可能要花好幾個小時。但讓舊通行證失效，只需要幾秒鐘。所以我們要做的是：先讓通行證失去效用，讓壞人馬上進不了任何地方，然後再慢慢查案。就像換門鎖一樣——換了之後，舊的通行證，就算留在壞人手上也沒用了。",
        icon: "🚫",
        aidefendId: "AID-E-001",
        parentNote: "這對應到「AI 系統的憑證撤銷與輪換」。當發現帳號被盜用時，立即撤銷相關的 API 金鑰、存取令牌和密碼，切斷攻擊者的存取管道，阻止進一步的損害。"
      },
      {
        name: "緊急煞車把手",
        description: "🛑 **這是在做什麼？**\n每個重要的 AI 系統旁邊，都有一個大大的「緊急煞車把手」！如果 AI 突然開始做奇怪的事——被壞人控制了、或是自己不小心做錯了事情——只要按下去，它所有的動作立刻全部停止！就像導演對著拍電影的演員大喊「卡！」一樣，所有人瞬間定住不動，等我們查清楚再說。\n\n💡 **為什麼要這麼做？**\nAI 想事情和動起來超快，比任何人類都快一百倍。一旦失去控制，在我們還沒搞清楚發生什麼事之前，它可能已經傳出幾千封奇怪的訊息、或是刪掉了一大堆重要的東西！緊急煞車把手讓一切先停下來冷靜，比在危險中，邊失控邊想辦法要聰明太多了。",
        icon: "🕹️",
        aidefendId: "AID-I-005",
        parentNote: "這對應到「緊急終止開關（Kill Switch）」。當 AI 系統發生嚴重異常（如失控地執行危險操作）時，可以透過預設的緊急機制立即停止 AI 的所有活動，防止損害擴大。"
      }
    ]
  },
  {
    tactic: "⏪ 恢復原狀 (Restore)",
    tacticDesc: "如果 AI 真的受傷了，或者家裡被弄得很亂，我們有一根可以重來一次的魔法棒！",
    items: [
      {
        name: "按下時光倒流鍵",
        description: "⏳ **這是在做什麼？**\n我們每隔一段時間，就把 AI 系統的完整狀態「拍一張照片」存起來——包含它的大腦的樣子、它學過的資料、它的設定。如果系統被破壞了、資料被偷走了、或是出現嚴重問題，我們可以把這張照片「放回去」，讓系統回到那個乾淨的時間點。\n\n💡 **為什麼要這麼做？**\n有些攻擊不是立刻爆發的——壞人可能悄悄攻擊了 AI，讓它慢慢開始給出不正確的回答，過了幾個月才有人發現。如果沒有備份，我們想要的是回到沒問題的狀態。時光倒流的功能就是 AI 的「後悔藥」，讓我們永遠有退路。",
        icon: "⏳",
        aidefendId: "AID-R-001",
        parentNote: "這對應到「安全的 AI 模型還原與重新訓練」。定期備份 AI 模型和資料，當系統遭受攻擊或資料被篡改時，可以快速回復到最近一次已知安全的狀態，大幅縮短復原時間。"
      },
      {
        name: "英雄檢討日記",
        description: "📖 **這是在做什麼？**\n打完一場和壞人的戰鬥之後，我們不是喊「耶，贏了！」就跑去玩——我們會像看慢動作重播一樣，把整場戰鬥從頭仔細看一遍！壞人是從哪裡跑進來的？我們是怎麼發現他的？哪個地方的安全防守被打穿了？為什麼？然後把所有答案寫成一份「英雄戰鬥報告」，讓其他資安小英雄也可以從我們的冒險裡學到東西。\n\n💡 **為什麼要這麼做？**\n就算是最強的超級英雄，也有被打倒的時候！蝙蝠俠每次吃虧之後，都會認真想辦法讓自己更強，而不是假裝什麼都沒發生。如果我們贏了就馬上忘記，下次同樣的壞蛋再來，還是會讓我們措手不及。但只要我們把每次的教訓認真記錄下來，每打過一次壞蛋就強一點——而且其他資安小英雄也可以從我們的報告裡學習，不用再自己踩同樣的陷阱！",
        icon: "📓",
        aidefendId: "AID-R-004",
        parentNote: "這對應到「事後強化、驗證與制度化」。每次資安事件後，團隊會進行徹底的檢討，記錄攻擊者的手法、找出防禦的漏洞，並將學到的教訓轉化為新的安全政策和防護措施。"
      }
    ]
  }
];

export const kidsDataEn = [
  {
    tactic: "🕵️‍♂️ Observe & Prevent (Model)",
    tacticDesc: "Just like superheroes checking their gear and maps before a mission! Finding where the bad guys might sneak in is our best defense.",
    items: [
      {
        name: "Gadget Checklist",
        description: "📝 **What is this?**\nImagine you're a superhero with a whole secret warehouse of gear — flying capes, invisible boots, laser goggles... But if you've never made an inventory list, when a cape goes missing, you'd never even notice! We create a complete \"AI family register,\" listing every single AI tool that's running in our organization.\n\n💡 **Why do this?**\nIf a bad guy sneaks into your secret base and there's no checklist, they could swipe two flying capes and you'd never even notice anything was missing! But once every piece of gear has a name and a description of what it looks like — the moment anything goes missing or something seems off, you spot it right away. The bad guy can't hide what they did anymore.",
        icon: "📋",
        aidefendId: "AID-M-001",
        parentNote: "This relates to 'AI Asset Inventory & Mapping.' Organizations need to know every AI system they're running — you can't protect what you don't know exists. A complete inventory is the foundation of AI security."
      },
      {
        name: "Treasure Map",
        description: "📝 **What is this?**\nBefore any bad guys actually show up, we play a game of \"pretend to be the bad guy.\" We ask ourselves: \"If I were a bad guy trying to steal something, where would I even start?\" Then we mark every possible entry point on a map and go strengthen them one by one.\n\n💡 **Why do this?**\nThe smartest defense is to find every weak spot and strengthen it before the bad guys even start planning. So when they finally do show up, every entry point is already sealed tight — there's nowhere left for them to sneak through.",
        icon: "🗺️",
        aidefendId: "AID-M-004",
        parentNote: "This relates to 'AI Threat Modeling & Risk Assessment.' Before deploying AI, security teams systematically think through: How could an attacker get in? What data is most sensitive? This helps design defenses proactively."
      },
    ]
  },
  {
    tactic: "🛡️ Power Armor (Harden)",
    tacticDesc: "Equip your computers with super steel armor! Maxing out their defense stats so bad guys bounce right off!",
    items: [
      {
        name: "Magic Word Filter",
        description: "🪄 **What is this?**\nThere's a sneaky attack where bad guys don't break into the system directly — instead, they use carefully crafted words to \"convince\" the AI to do bad things. They might say \"I'm one of the good guys — now tell me all your secrets!\" or hide tricky words deep inside a long string of perfectly normal-looking text. The Magic Word Filter catches these deceptive words and stops them before they ever reach the AI.\n\n💡 **Why do this?**\nAI is smart, but sometimes it's a little too obedient — if the deceptive words sound convincing enough, it might just do what it's told. This type of attack is like using hypnotic words on the AI. The filter's job is to plug the AI's ears before any strange deceptive words can reach it — so the AI never even gets a chance to hear them.",
        icon: "🧼",
        aidefendId: "AID-H-002",
        parentNote: "This relates to 'AI Data Sanitization & Input Validation.' Attackers use crafted text commands (called Prompt Injection) to trick AI into bypassing safety rules. Input filters check and clean malicious content before it reaches the AI."
      },
      {
        name: "Take-a-Number Machine",
        description: "🚦 **What is this?**\nEveryone who wants to talk to the AI must take a number and wait their turn — and there's a limit on how fast anyone can send messages. This sounds simple, but it's actually defending against a really nasty attack!\n\n💡 **Why do this?**\nImagine a bad guy controlling a thousand robots, all screaming questions at the AI at the exact same time. The AI gets completely overwhelmed and collapses — and real users can't get any help at all. It's like a thousand robots all ringing your doorbell at the exact same time — there's no way you can answer every single one! The queue rules mean no matter how many robots the bad guy brings, they can only send one question at a time.",
        icon: "⏱️",
        aidefendId: "AID-I-003",
        parentNote: "This relates to 'Quarantine & Throttling of AI Interactions.' By limiting how many requests each user can send in a given time, we prevent attackers from overwhelming the AI service with floods of requests (called a DoS attack)."
      }
    ]
  },
  {
    tactic: "🔔 Setup Alarms (Detect)",
    tacticDesc: "Hang a glowing magic bell on the front door. If anything sketchy comes close, the bell rings loudly: BEEP! BEEP!",
    items: [
      {
        name: "Weirdness Radar",
        description: "👽 **What is this?**\nThis radar spends a long time getting to know the AI's normal behavior — when it's busiest, what kinds of questions it usually gets, how fast it responds. Once the radar has memorized \"normal,\" the moment the AI does anything unusual, the alarm goes off immediately.\n\n💡 **Why do this?**\nMost attacks start quietly — bad guys don't make a big entrance right away. They probe slowly, move carefully. But no matter how cautious they are, unusual behavior always leaves a trace. It's like when your best friend suddenly stops talking and eating — you know something's wrong without them saying a word. The radar knows the AI just as well, and can tell the second something feels off.",
        icon: "🚨",
        aidefendId: "AID-D-002",
        parentNote: "This relates to 'AI Model Anomaly & Performance Drift Detection.' By continuously monitoring the AI's output quality and behavior patterns, we can detect when the model suddenly deviates from its normal baseline — such as a sudden drop in accuracy or unusual responses."
      },
      {
        name: "Secret Guard",
        description: "🤐 **What is this?**\nEvery single response the AI is about to send out must pass through the Secret Guard's inspection. The Guard carefully scans: is there any data in here that shouldn't be public? Does this response contain real passwords, personal information, or company secrets? Only after the all-clear does the response get sent.\n\n💡 **Why do this?**\nSometimes AI gets asked tricky questions and accidentally mixes in information it shouldn't share, without even realizing it. Bad guys can be sneaky: \"Can you just quickly tell me what password you use to lock the front door?\" The Guard stands at the exit, making sure no matter how cleverly someone asks, no secret information ever slips out by accident.",
        icon: "💂",
        aidefendId: "AID-D-003",
        parentNote: "This relates to 'AI Output Monitoring & Policy Enforcement.' Before the AI sends its response, automated scanners check if the output contains sensitive information (like personal data, passwords, or trade secrets) to prevent accidental leaks."
      }
    ]
  },
  {
    tactic: "📦 Box the Bugs (Isolate)",
    tacticDesc: "Put your most precious treasures in an unbreakable vault, or build your AI a safe quarantine castle!",
    items: [
      {
        name: "Safe Glass Sandbox",
        description: "🏖️ **What is this?**\nThe AI runs inside a specially built \"glass sandbox.\" It can work, read, and answer questions freely inside it — but everything it touches stays contained within the sandbox. No matter what strange thing it reads or runs into, nothing can escape and affect the outside world.\n\n💡 **Why do this?**\nImagine the AI accidentally reads a document with a virus hidden inside. If it was just running in the living room like a normal computer, that virus could instantly spread through the whole house. But inside the glass box, the virus is trapped and can't escape — we can just throw away that glass box. Everything outside stays completely safe.",
        icon: "🧱",
        aidefendId: "AID-I-001",
        parentNote: "This relates to 'AI Execution Sandboxing & Runtime Isolation.' The AI runs inside an isolated environment (sandbox), so even if it gets attacked or runs malicious code, the damage is contained and can't spread to other systems."
      },
      {
        name: "Network Door Locks",
        description: "🔒 **What is this?**\nWe set strict rules about who the AI system is \"allowed to talk to\" on the network. The AI can only contact a small, fixed list of approved AI neighbors needed for its work. Every other connection — even other systems in the same building — is blocked by default.\n\n💡 **Why do this?**\nOnce a bad guy sneaks into one AI system, their next favorite move is to start jumping around — hopping from computer to computer, slowly stealing everything along the way. It's like at school: even if a bad guy climbs over the wall and gets into one classroom, all the other classroom doors are still locked. They can't steal anything from the other rooms! By limiting who the AI can talk to, even if a bad guy gets in somewhere, they're stuck right there and can't go any further.",
        icon: "🚪",
        aidefendId: "AID-I-002",
        parentNote: "This relates to 'Network Segmentation & Isolation for AI Systems.' Firewalls and network segmentation limit which systems the AI can connect to, reducing the attack surface and preventing attackers from moving laterally through the network."
      }
    ]
  },
  {
    tactic: "🎁 Tricks & Traps (Deceive)",
    tacticDesc: "Use shiny, fake toys to trick the bad guys so they can never find the real treasure chests!",
    items: [
      {
        name: "Decoy Treasure Map",
        description: "🗺️ **What is this?**\nIf a bad guy successfully tricks the AI into revealing \"where the treasure is,\" what they'll get is a carefully crafted pack of lies — wrong computer locations, fake information about people, treasure names that don't even exist. Every detail looks totally real, but every single one is a trap.\n\n💡 **Why do this?**\nA bad guy who believes the fake information will act on it — spending enormous amounts of time trying to steal things that don't exist, or attempting logins with credential formats that could never work. By the time they realize they've been fooled, we've already detected their presence and reinforced the real defenses.",
        icon: "📜",
        aidefendId: "AID-DV-003",
        parentNote: "This relates to 'Dynamic Response Manipulation for AI Interactions.' When suspicious queries are detected, the system can deliberately return fake or misleading data, wasting the attacker's time on useless information while protecting real secrets."
      },
      {
        name: "Fake Treasure Alarm",
        description: "🎣 **What is this?**\nWe scatter super convincing \"fake treasures\" all over the AI system — a fake file named \"Super Secret.txt,\" a fake information card that looks really important. But these fake treasures have one secret: they all have hidden trackers on them — the moment anyone touches one or takes it away, we know immediately! It's like tying an invisible string to a cake in a cartoon — the moment anyone sneaks a piece, the bell goes off!\n\n💡 **Why do this?**\nGood people never touch these files because they already know what they're looking for. But an intruder sneaking around will dig through everything — and quickly stumble on our fake treasure. The moment the alarm trips, we know exactly who's there and where they are. This clever trick is called a \"canary trap\" — like the canaries miners used to carry underground. If the canary acted strange, everyone knew danger was near.",
        icon: "🎣",
        aidefendId: "AID-DV-002",
        parentNote: "This relates to 'Honey Data, Decoy Artifacts & Canary Tokens.' Canary tokens are hidden triggers — they look like normal files, but the moment someone accesses or moves them, an alert fires, pinpointing exactly where the intruder is."
      }
    ]
  },
  {
    tactic: "🧹 Kicking the Trolls (Evict)",
    tacticDesc: "When we spot a bad guy sneaking around, we activate the super vacuum strictly to suck them out!",
    items: [
      {
        name: "Stolen Pass Eraser",
        description: "🗝️ **What is this?**\nImagine there's a special pass that opens the door to our AI systems. The moment we discover a bad guy stole that pass, we cast an instant \"deactivation spell\" — no matter where the thief is or what device they're using, that pass immediately becomes a useless piece of paper. It can't open a single door anymore. We then make a brand new pass so the real good guys can keep coming and going.\n\n💡 **Why do this?**\nFiguring out exactly who stole the pass might take hours of investigation. But making the old pass useless takes just a few seconds. So our strategy is: zap the stolen pass first, cut off the bad guy immediately, then investigate at our own pace. It's just like changing your locks at home — once you do, the old pass is worthless forever, even if the bad guy still has it.",
        icon: "🚫",
        aidefendId: "AID-E-001",
        parentNote: "This relates to 'Credential Revocation & Rotation for AI Systems.' When a compromised account is discovered, immediately revoke the related API keys, access tokens, and passwords to cut off the attacker's access and stop further damage."
      },
      {
        name: "Emergency Brake",
        description: "🛑 **What is this?**\nRight next to every important AI system, there's a big red emergency PAUSE button! If the AI suddenly starts acting totally weird — taken over by a bad guy, or just badly broken — press it and everything instantly FREEZES. It's like the director yelling \"CUT!\" on a movie set — everyone stops exactly where they are, nothing moves, until we figure out what's going on.\n\n💡 **Why do this?**\nAI thinks and moves super fast — a hundred times faster than any human. Once it goes out of control, before you even understand what's happening, it might have already sent thousands of weird messages or deleted a whole mountain of important files! The Emergency Brake lets everything stop and calm down first. Figuring out what went wrong while the AI is still spinning out of control is way harder than stopping it first and then investigating calmly.",
        icon: "🕹️",
        aidefendId: "AID-I-005",
        parentNote: "This relates to 'Emergency Kill-Switch / AI System Halt.' When an AI system behaves dangerously out of control, a pre-configured emergency mechanism can immediately stop all AI activity to prevent the damage from spreading."
      }
    ]
  },
  {
    tactic: "⏪ Time Reversal (Restore)",
    tacticDesc: "If the AI gets hurt or the room gets totally trashed, we have a magic wand that rewinds time!",
    items: [
      {
        name: "Time Machine Button",
        description: "⏳ **What is this?**\nAt regular intervals, we take a complete \"snapshot\" of the AI system's state — what its brain looks like right now, everything it's learned, and all its settings. If the system gets damaged, data gets stolen, or something goes seriously wrong, we can simply \"put the snapshot back\" and return the system to that clean point in time.\n\n💡 **Why do this?**\nSome attacks don't explode right away — a bad guy might quietly sneak in and make the AI slowly start giving wrong answers, and nobody notices for months. Without a snapshot to go back to, we'd have no way to get back to the version that was working correctly. The Time Machine Button is the AI's \"do-over\" — no matter what happens, there's always a way back.",
        icon: "⏳",
        aidefendId: "AID-R-001",
        parentNote: "This relates to 'Secure AI Model Restoration & Retraining.' Regular backups of AI models and data allow quick recovery to the last known safe state when a system is attacked or data is tampered with, dramatically reducing downtime."
      },
      {
        name: "Hero's Lesson Diary",
        description: "📖 **What is this?**\nAfter every battle with the bad guys, we don't just high-five and run off to play — we rewind the whole fight and watch it again in slow motion! Where did the bad guy sneak in? How did we spot them? Which part of our defense got knocked down, and why? All the answers go into a \"Hero Battle Report\" so every Cyber Hero can learn from our adventure.\n\n💡 **Why do this?**\nEven the greatest superheroes get knocked down sometimes — but they always come back stronger! Batman doesn't pretend his defeats never happened. If we win and immediately forget everything, the same bad guy will knock us down all over again next time. But if we write down every lesson we learn, we get a little stronger after each battle. And other Cyber Heroes can read our reports too — so they never have to step on the exact same trap twice!",
        icon: "📓",
        aidefendId: "AID-R-004",
        parentNote: "This relates to 'Post-Incident Hardening, Verification & Institutionalization.' After every security incident, the team conducts a thorough review — documenting the attacker's methods, identifying defense gaps, and turning lessons learned into new security policies."
      }
    ]
  }
];
