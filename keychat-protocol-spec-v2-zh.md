# Keychat 协议规范 v2

> **版本**: 2.0 草案 — 2026-03-13
> **用途**: 开发者从零实现一个完全互操作的 Keychat 客户端所需的一切信息。

---

## 目录

1. [概述](#1-概述)
2. [身份层（Nostr）](#2-身份层nostr)
3. [传输层（Nostr 中继）](#3-传输层nostr-中继)
4. [消息格式（KCMessage v2）](#4-消息格式kcmessage-v2)
5. [加密层](#5-加密层)
6. [添加联系人（好友请求）](#6-添加联系人好友请求)
7. [接受好友请求](#7-接受好友请求)
8. [Signal 加密 1:1 聊天](#8-signal-加密-11-聊天)
9. [接收地址轮换](#9-接收地址轮换)
10. [Signal 群组（sendAll）](#10-signal-群组sendall)
11. [MLS 群组](#11-mls-群组)
12. [媒体与文件传输](#12-媒体与文件传输)
13. [Ecash 邮票](#13-ecash-邮票)
14. [密码学原语参考](#14-密码学原语参考)
15. [实现检查清单](#15-实现检查清单)

---

## 1. 概述

Keychat 协议是一个主权通信协议栈，集成五个层级：

| 层级 | 技术 | 用途 |
|------|------|------|
| **身份层** | Nostr secp256k1 密钥对（npub/nsec） | 自托管，无服务器依赖 |
| **传输层** | Nostr 中继网络 | 开放且可自建的消息路由 |
| **加密层** | Signal Protocol + PQXDH（1:1 及小群组）、MLS（大群组） | 端到端加密，具备抗量子安全性 |
| **寻址层** | 棘轮派生的临时地址 | 收发地址与身份解耦，持续轮换 |
| **邮票层** | Cashu ecash token | 向中继的匿名微支付，用于消息投递 |

### 核心设计原则

1. **Signal 作为纯加密层**：Keychat 将 Signal Protocol 抽象为可替换的加密原语。Signal 只负责加密和解密——身份、传输、寻址和投递全部由其他层处理。Signal 身份（Curve25519 密钥对）是**临时的、逐对端的**：为每个联系人生成新的 Signal 身份，会话重置时丢弃并重新生成。用户的永久身份是 Nostr 密钥对，而非任何 Signal 密钥。
2. **发送者匿名**：每条消息均从随机的临时 Nostr 密钥对发出。发送者的真实 npub 永远不会以 Nostr 事件作者的身份出现。
3. **接收者不可关联**：接收者地址随每次 Double Ratchet 步骤轮换，从棘轮状态确定性派生。地址与身份解耦——中继和观察者都无法将消息与任何一方关联。
4. **统一传输**：所有消息使用 Nostr 事件 kind 1059，无论加密协议是什么。
5. **抗量子安全**：初始密钥协商使用 PQXDH（Signal 的混合经典+后量子协议），将 Curve25519 ECDH 与 ML-KEM 1024（Kyber）密钥封装相结合。
6. **经济反垃圾**：Cashu ecash 邮票作为向中继的匿名微支付，实现无需账户或身份披露的无许可消息投递。

### 会话类型

| 会话类型 | 协议 | 加密模型 | 密钥轮换 | 最大成员数 |
|---------|------|---------|---------|-----------|
| Signal 1:1 | Signal（PQXDH + Double Ratchet） | 点对点会话 | 每条消息棘轮 | 2 |
| Signal 群组 | Signal sendAll | 对每个成员点对点加密 | 每条消息棘轮 | ~50 |
| MLS 群组 | MLS（RFC 9420） | 共享群密钥（棘轮树） | 每纪元 Commit | 数千 |

---

## 2. 身份层（Nostr）

Keychat 身份是按照 [NIP-06](https://github.com/nostr-protocol/nips/blob/master/06.md) 派生的标准 Nostr secp256k1 密钥对：

```
BIP-39 助记词（12 或 24 个词）
  → BIP-39 种子（可选 passphrase）
  → BIP-32 派生路径：m/44'/1237'/<account>'/0/0
  → secp256k1 密钥对
  → 公钥（hex，64 字符）= Nostr 身份
  → npub（bech32 编码）
  → nsec（私钥的 bech32 编码）
```

派生路径遵循 [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) 的 coin type 1237（Nostr）。基础客户端使用 `account = 0`。高级客户端可递增 `account` 从同一助记词派生多个独立身份。

这是用户的**永久主权身份**，用于：
- 签名 Nostr 事件
- NIP-44 加密（Gift Wrap）
- 长期可发现地址（他人通过 npub 添加你）
- 身份绑定的 Schnorr 签名（`globalSign`）

### 2.1 密钥存储安全

BIP-39 助记词和派生的私钥（nsec）是**所有身份和加密的根**。这些密钥泄露意味着身份完全丧失。实现**必须**：

1. **绝不将助记词或私钥存储在明文配置文件中**（如 JSON、YAML、TOML 配置文件，这些文件可能被版本控制或被其他用户读取）。
2. **优先使用硬件安全存储**（推荐）：
   - **iOS/macOS**：Keychain Services（`Security.framework`）或 Secure Enclave
   - **Android**：Android Keystore 系统（可用时使用硬件支持）
   - **有安全硬件的桌面**：TPM 支持的凭据存储
3. **硬件不可用时，退回到软件安全存储**（推荐）：
   - **OS keyring**：`libsecret`/GNOME Keyring、KWallet、macOS Keychain（软件模式）
   - **加密的 secrets 文件**：专用文件（如 `secrets/mnemonic`），设置受限权限（mode `0600`），理想情况下用用户口令或独立管理的密钥加密
   - **环境变量**：适用于临时/容器化部署（如 Docker secrets、systemd credentials 安全注入），但**不适用于**磁盘持久化存储
4. **避免明文文件存储**（不推荐）：将助记词存储在无加密、无权限限制的普通文件中是强烈不建议的。如果没有更好的选择，文件**必须**至少设置 mode `0600`（仅所有者可读）。
5. **不再使用时从内存中清零私钥材料**（使用 `zeroize` crate 或等效机制）。
6. **创建身份时不显示助记词**。直接存入安全存储。仅当用户主动请求备份时，经过身份验证（生物识别、PIN 或 owner 认证）后才显示。绝不记录日志、绝不包含在崩溃报告或诊断信息中。

> **存储优先级**（从高到低）：
> 1. 硬件安全元件（Secure Enclave、TPM、Android Keystore）
> 2. OS keyring / Keychain（软件级）
> 3. 加密的 secrets 文件（口令保护，mode `0600`）
> 4. 受限权限的明文文件（mode `0600`，最后手段）
>
> 实现**应当**优先尝试高优先级选项，优雅降级。对于 daemon/无人值守部署（无法弹出交互式 keychain 授权），加密的 secrets 文件或安全注入的环境变量是预期路径。

> **理由**：助记词等同于用户身份。不同于 Signal Protocol 密钥（临时的、逐对端的），Nostr 密钥对是永久的——泄露后无法通过会话重置恢复。它需要与加密货币种子短语相同级别的保护。

### 2.2 多 Agent 身份隔离

每个 Agent 实例必须拥有**独立的身份**——独立的 BIP-39 助记词、独立的 Nostr 密钥对（npub/nsec）、独立的 Signal 会话、独立的加密数据库。Agent 之间不共享任何密钥材料。

当同一台主机上运行多个 Agent 时（例如一台服务器上的多个 AI Agent），每个 Agent：

1. **首次启动时生成自己的助记词**——按公钥分别存储在 OS Keychain 中。
2. **拥有独立的 npub**——用户需要分别添加每个 Agent 为好友。
3. **维护独立的状态**——独立的数据目录、独立的联系人列表、独立的 Signal 会话、独立的地址管理器。不共享任何状态。
4. **运行独立的 daemon**（daemon 模式下）——独立端口、独立数据目录。

这确保了：
- **泄露隔离**：一个 Agent 的密钥泄露不影响同主机上的其他 Agent。
- **身份语义清晰**：每个 npub 对应一个有明确用途的 Agent。用户知道自己在和谁对话。
- **无路由歧义**：每个 Agent 独立管理自己的收信地址和 relay 订阅。

> **示例**：一个 OpenClaw 实例同时运行私人助理 Agent 和代码审查 Agent。每个有自己的 npub。用户在 Keychat 客户端中分别添加两者为好友，独立聊天。

所有 Signal Protocol 密钥材料（Curve25519 身份密钥、签名预密钥、一次性预密钥、Kyber KEM 密钥）属于**加密层**，是**临时的、逐对端的、可丢弃的**。为每个联系人生成新的 Signal 身份；会话重置时丢弃并重新生成。Signal 身份不属于用户身份的一部分——它们是用户永远不需要看到或管理的内部加密状态。

### 2.3 Owner 管理（仅 Agent 模式）

> **适用范围**：本节仅适用于 **agent 部署**（以 daemon 运行的 AI agent）。人类用户的 Keychat 客户端没有 "owner" 概念——用户直接控制自己的身份。

每个 agent 有一个 **owner** —— 拥有该 agent 管理权限的人类管理员的 Nostr 身份（npub）。Owner 可以批准/拒绝其他 peer 的好友请求，以及执行助记词备份等敏感操作。

**Owner 分配**：
- 首次启动时，agent 没有 owner。第一个发送好友请求的 peer 被自动接受并成为 owner。
- 后续好友请求需要 owner 批准。

**Owner 转移**（例如 owner 设备丢失时）：
- Agent daemon 暴露 `POST /set-owner` 端点，仅绑定 `127.0.0.1`——不可从网络访问。
- 该端点接受新 owner 的公钥（npub 或 hex），或 `null` 清空 owner（下一个好友请求自动成为 owner）。
- **授权模型**：`/set-owner` API 在 HTTP 层不做认证——安全性依赖于 localhost 绑定。当 AI agent 框架（如 OpenClaw）管理 daemon 时，owner 变更**必须**仅在请求来自已验证的平台 owner 时执行，不能因为任意聊天消息就执行。聊天消息（包括 Keychat）**不能**作为 owner 身份的证明。

---

## 3. 传输层（Nostr 中继）

### 3.1 中继连接

通过 WebSocket（`wss://`）**同时**连接到**多个** Nostr 中继。所有通信使用标准 Nostr 中继协议（NIP-01）：

- **发布**：`["EVENT", <event_json>]` 或 `["EVENT", <event_json>, <ecash_token>]`（ecash 邮票是 Keychat 的中继协议扩展，非标准 NIP-01）
- **订阅**：`["REQ", <subscription_id>, <filter>]`
- **取消订阅**：`["CLOSE", <subscription_id>]`

#### 多中继广播

实现**必须**支持同时连接多个中继，并且**必须**将每条发布的事件同时广播到**所有**已连接的中继。这提供了：

- **冗余性**：如果某个中继宕机或审查事件，消息仍可通过其他中继到达接收方。
- **可用性**：接收方订阅相同的中继集合，从最先送达的中继接收事件。
- **抗审查**：没有单个中继可以阻断通信。

订阅也**必须**在所有已连接的中继上注册。去重机制确保即使从多个中继收到同一事件，也只处理一次。

发布操作在**至少一个**中继接受事件时即视为成功。实现应当记录中继级别的失败，但除非所有中继都拒绝了事件，否则**不得**将发送操作视为失败。

推荐默认中继：`wss://nos.lol`、`wss://relay.damus.io`。实现应当允许用户自定义中继列表。

### 3.2 统一事件类型

所有 Keychat 消息使用 **kind 1059** 作为传输事件，无论使用何种加密协议。唯一的例外是 MLS KeyPackage 发布，使用 kind 10443。

| Kind | 用途 |
|------|------|
| **1059** | 所有消息传输（Signal、MLS、NIP-17 Gift Wrap） |
| **10443** | MLS KeyPackage（可替换事件，直接发布） |

### 3.3 两种传输模式

#### 模式一：直接传输（Signal / MLS 加密消息）

Signal 和 MLS 消息已在应用层完成端到端加密。它们直接作为 kind 1059 事件传输，无需额外的 Nostr 层加密：

```
Kind 1059 事件：
  pubkey:      临时一次性密钥（不是发送者的真实 pubkey）
  created_at:  真实当前时间戳（不做随机偏移）
  tags:        [["p", <接收者地址>]]
  content:     base64(signal 或 mls 密文)
```

**注意**：与 NIP-17 Gift Wrap 不同，模式一使用**真实时间戳**——不做随机偏移。内容已被 Signal/MLS 加密，时间戳随机化不提供额外的隐私收益。

适用于：
- Signal 1:1 消息
- Signal 群组消息（逐成员加密）
- MLS 群组应用消息和 Commit
- 与目标成员已有 Signal 会话时的 `mlsGroupInvite`

#### 模式二：NIP-17 Gift Wrap（未加密载荷）

当不存在 Signal 会话时（如好友请求），NIP-17 三层包装提供加密和元数据保护：

```
第三层：Gift Wrap（kind 1059）
  pubkey:      临时密钥（不是发送者的真实 pubkey）
  created_at:  真实当前时间戳（不做偏移）
  content:     NIP-44 加密(临时私钥, 接收者公钥) →
    第二层：Seal（kind 13）
      pubkey:    发送者真实公钥
      content:   NIP-44 加密(发送者真实私钥, 接收者公钥) →
        第一层：Rumor（未签名事件）
          kind:    14
          tags:    [["p", <接收者公钥>]]
          content: KCMessage JSON 明文
```

> **Keychat 与 NIP-17 的差异**：标准 NIP-17 建议在 Gift Wrap 层使用随机时间戳偏移（0–2 天）。Keychat 的**所有 kind 1059 事件均使用真实时间戳**，包括 Gift Wrap。中继按 `since` 过滤——偏移后的时间戳可能导致接收者看不到事件。由于发送者匿名性已通过临时 pubkey 实现，时间戳偏移对 Keychat 的场景不提供有意义的额外隐私。

> **注意**：构建 Gift Wrap 需要**两组密钥**：发送者的真实身份密钥（用于 Seal 层）和临时密钥对（用于外层 Gift Wrap）。Seal 将消息绑定到真实发送者；Gift Wrap 对中继隐藏真实发送者。

适用于：
- `friendRequest`（尚无 Signal 会话）
- 与目标成员无 Signal 会话时的 `mlsGroupInvite`

### 3.4 四种收信地址

Keychat 客户端最多同时监听四种类型的收信地址：

#### 类型一：身份 npub（永久）

你的 Nostr 身份公钥。始终监听。用于：
- **入站好友请求** — 当他人向你发送 `friendRequest` 时，消息通过 NIP-17 Gift Wrap 投递到你的 npub。
- **非好友的 MLS 群邀请** — 当他人将你加入 MLS 群但与你没有 1:1 Signal 会话时，`mlsGroupInvite` 通过 NIP-17 发送到你的 npub。

#### 类型二：firstInbox（临时，每次出站好友请求）

当你向他人发送好友请求时，生成一个新的 `firstInbox` 密钥对，将公钥包含在请求中。你监听此地址以接收对方的回复（同意或拒绝）。

**不一定是一次性的**：对方发送同意消息后，可能紧接着又发了几条消息，这些消息也发送到同一个 `firstInbox` 地址。`firstInbox` 在你收到发往棘轮派生地址的消息后清除，此时确认棘轮已激活。

#### 类型三：Signal DH 棘轮派生收信地址（动态，每对端）

最常用的收信地址。从 Signal Double Ratchet 状态派生（见 §9）。

**生命周期**：当 Bob 发出同意 Alice 好友请求的消息时，棘轮初始化。Bob 计算出自己的首个棘轮收信地址并开始监听，等待 Alice 的回复。当 Alice 解密 Bob 的同意消息时，她推导出 Bob 的棘轮收信地址（用于发送），同时也推进了自己的棘轮，产生了她自己的收信地址。从此之后，Alice 和 Bob 之间的所有消息都使用棘轮派生地址，每次方向改变时轮换。

每对端维护 2–3 个地址的滑动窗口（见 §9.3）。

#### 类型四：MLS 派生收信地址（动态，每 MLS 群）

仅用于 MLS 大群。每个成员从 MLS export secret 派生共享收信地址（`mlsTempInbox`）。同纪元内所有成员计算出相同的地址。此地址在每次 MLS Commit 后轮换（见 §11.2）。

#### 订阅过滤器

```json
{
  "kinds": [1059],
  "#p": [
    "<npub>",
    "<firstInbox_1>", "<firstInbox_2>",
    "<棘轮地址_peer1_a>", "<棘轮地址_peer1_b>",
    "<棘轮地址_peer2_a>", "<棘轮地址_peer2_b>",
    "<mls_temp_inbox_群1>", "<mls_temp_inbox_群2>",
    ...
  ],
  "since": <unix 时间戳>
}
```

### 3.5 接收端路由

当 kind 1059 事件到达时，接收端通过匹配 `p`-tag 目标地址判断消息类型：

```
收到 kind 1059 事件：
  ├── p-tag 匹配 room.mlsTempInbox？
  │     → MLS 消息（模式一），用 MLS 解密
  │
  ├── p-tag 匹配某个 Signal 棘轮接收地址？
  │     → Signal 消息（模式一），用 Signal Protocol 解密
  │
  └── 都不匹配？
        → 尝试 NIP-17 Gift Wrap 解包（模式二）
        → 解析 KCMessage.kind 进行路由（friendRequest、mlsGroupInvite 等）
```

---

## 4. 消息格式（KCMessage v2）

所有结构化消息使用 KCMessage v2 信封。这是放入加密载荷（Signal/MLS）或 NIP-17 Rumor（Gift Wrap）内部的内容。

### 4.1 信封结构

```json
{
  "v": 2,
  "id": "<uuid-v4>",
  "kind": "<KCMessageKind>",
  "<载荷字段>": { ... },
  "groupId": "<群公钥>",
  "replyTo": { ... },
  "signalPrekeyAuth": { ... },
  "fallback": "<人类可读的降级文本>",
  "threadId": "<根消息 id>",
  "forwardFrom": { ... },
  "burnAfterReading": true
}
```

### 4.2 信封字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `v` | `int` | 是 | 协议版本，必须为 `2` |
| `kind` | `string` | 是 | 消息类型标识符（见 §4.4） |
| `id` | `string?` | 否 | 消息 UUID v4。群消息、taskRequest/taskResponse、friendRequest 必填，其他推荐填写 |
| `groupId` | `string?` | 否 | 群公钥。群消息时存在，1:1 消息时缺省 |
| `replyTo` | `ReplyTo?` | 否 | 回复引用（见 §4.6） |
| `signalPrekeyAuth` | `SignalPrekeyAuth?` | 否 | PrekeyMessage 的身份绑定（见 §4.6 SignalPrekeyAuth） |
| `fallback` | `string?` | 否 | 客户端不识别 `kind` 时显示的人类可读文本 |
| `threadId` | `string?` | 否 | 子会话/话题的根消息 ID |
| `forwardFrom` | `ForwardFrom?` | 否 | 转发消息的原始发送者信息 |
| `burnAfterReading` | `bool?` | 否 | 阅后即焚标记 |

### 4.3 设计原则

1. **扁平枚举分发** — 单一的 `kind` 字段路由所有消息类型。
2. **类型化载荷** — 每个 `kind` 对应恰好一个载荷字段。
3. **协议无关** — 消息体不包含加密元数据（v1 的 `MessageType c` 已移除）。加密和传输由外部处理。
4. **版本化** — `v: 2` 区分新格式。
5. **前向兼容** — 未知的 `kind` 值通过 `fallback` 字段优雅降级。
6. **大小限制** — 序列化后的 KCMessage 不应超过 64KB。更大的内容应使用 `files` kind 加密上传。

### 4.4 KCMessageKind 枚举

#### 命名约定

| 范围 | 前缀 | 示例 |
|------|------|------|
| 通用（所有协议） | 无 | `text`、`files`、`cashu`、`location` |
| 消息操作 | `message` | `messageDelete`、`messageEdit` |
| 群组通用操作 | `group` | `groupPinMessage`、`groupAnnouncement` |
| Signal 1:1 | 无 | `friendRequest`、`profileSync` |
| Signal 群组（sendAll） | `signal` | `signalGroupInvite`、`signalGroupDissolve` |
| MLS 群组 | `mls` | `mlsGroupInvite` |
| Agent（交互类） | `agent` | `agentActions`、`agentOptions`、`agentConfirm` |
| Agent（协议类） | 无 | `taskRequest`、`skillQuery`、`eventNotify` |

#### 核心 Kind

| Kind | 载荷字段 | 说明 |
|------|---------|------|
| `text` | `text` | 文本消息 |
| `files` | `files` | 文件、图片、视频、音频、语音 |
| `cashu` | `cashu` | Ecash token 转账 |
| `lightningInvoice` | `lightning` | Lightning invoice |

#### Signal 1:1 Kind

| Kind | 载荷字段 | 说明 |
|------|---------|------|
| `friendRequest` | `friendRequest` | 带 PQXDH 预密钥包的好友请求（通过 NIP-17） |
| `friendApprove` | `friendApprove` | 同意好友请求（关联请求 ID） |
| `friendReject` | `friendReject` | 拒绝好友请求（关联请求 ID） |
| `profileSync` | `profile` | 资料同步 |
| `relaySyncInvite` | `relaySync` | 中继同步邀请（本地确认，不发送回复） |

#### Signal 群组 Kind

| Kind | 载荷字段 | 说明 |
|------|---------|------|
| `signalGroupInvite` | `signalGroupInvite` | 管理员发送群邀请（含 RoomProfile） |
| `signalGroupMemberRemoved` | `signalGroupAdmin` | 管理员移除成员 |
| `signalGroupSelfLeave` | `signalGroupAdmin` | 成员主动退群 |
| `signalGroupDissolve` | `signalGroupAdmin` | 管理员解散群组 |
| `signalGroupNameChanged` | `signalGroupAdmin` | 管理员改群名 |
| `signalGroupNicknameChanged` | `signalGroupAdmin` | 成员改昵称 |

#### MLS 群组 Kind

| Kind | 载荷字段 | 说明 |
|------|---------|------|
| `mlsGroupInvite` | `mlsGroupInvite` | MLS 群邀请（通过 Signal 或 NIP-17） |

> **MLS 管理操作**（添加/移除成员、重命名、解散、密钥更新）通过 MLS Commit 在协议层执行，不使用 KCMessage kind。见 §11。

#### Agent Kind

| Kind | 载荷字段 | 类别 | 说明 |
|------|---------|------|------|
| `agentActions` | `agent` | 交互类 | 操作菜单（类似 Telegram Bot 命令） |
| `agentOptions` | `agent` | 交互类 | 选项列表（单选或多选） |
| `agentConfirm` | `agent` | 交互类 | 确认对话框 |
| `agentReply` | `agent` | 交互类 | 用户对任何 Agent 交互的回复 |
| `taskRequest` | `taskRequest` | 协议类 | 任务委托请求 |
| `taskResponse` | `taskResponse` | 协议类 | 任务执行结果 |
| `skillQuery` | 无 | 协议类 | 能力发现查询（空载荷） |
| `skillDeclare` | `skillDeclare` | 协议类 | 能力声明 |
| `eventNotify` | `eventNotify` | 协议类 | 单向事件通知 |
| `streamChunk` | `streamChunk` | 协议类 | 流式中间输出 |

#### 其他 Kind

| Kind | 载荷字段 | 说明 |
|------|---------|------|
| `reaction` | `reaction` | 添加/移除 emoji 回应 |
| `messageDelete` | `messageDelete` | 撤回/删除消息 |
| `messageEdit` | `messageEdit` | 编辑已发送的消息 |
| `readReceipt` | `readReceipt` | 已读回执 |
| `typing` | 无 | 正在输入指示（临时信号，不存储） |
| `location` | `location` | 位置分享 |
| `contact` | `contact` | 联系人名片分享 |
| `sticker` | `sticker` | 贴纸/表情包 |
| `poll` | `poll` | 创建投票 |
| `pollVote` | `pollVote` | 投票 |
| `callSignal` | `callSignal` | 通话信令（offer/answer/reject/end/ICE） |
| `groupPinMessage` | `groupPinMessage` | 置顶/取消置顶群消息 |
| `groupAnnouncement` | `groupAnnouncement` | 群公告 |

### 4.5 核心载荷定义

#### KCTextPayload

```json
{
  "v": 2,
  "kind": "text",
  "text": {
    "content": "Hello, world!",
    "format": "plain"
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `content` | `string` | 是 | 消息文本 |
| `format` | `string?` | 否 | `"plain"`（默认）或 `"markdown"`。Markdown 渲染必须禁止原始 HTML |

#### KCFilesPayload

```json
{
  "v": 2,
  "kind": "files",
  "files": {
    "message": "今天的照片",
    "items": [
      {
        "category": "image",
        "url": "https://example.com/encrypted/abc123",
        "type": "image/jpeg",
        "suffix": "jpg",
        "size": 245760,
        "key": "aes256-key-hex",
        "iv": "iv-hex",
        "hash": "sha256-hex"
      }
    ]
  }
}
```

**KCFilesPayload**：`message`（可选文本）、`items`（KCFilePayload 列表）。

**KCFilePayload 字段**：`category`（FileCategory 枚举）、`url`、`type`（MIME）、`suffix`、`size`（字节）、`key`（AES hex）、`iv`（hex）、`hash`（SHA256 hex）、`sourceName`、`audioDuration`（秒）、`amplitudeSamples`（波形）、`ecashToken`。

**FileCategory 枚举**：`image`、`video`、`voice`、`audio`、`document`、`text`、`archive`、`other`。

#### KCFriendRequestPayload

用于建立 PQXDH Signal 会话的预密钥包。通过 NIP-17 Gift Wrap（模式二）发送。

```json
{
  "v": 2,
  "id": "fr-uuid-001",
  "kind": "friendRequest",
  "friendRequest": {
    "message": "你好，我是 Alice。让我们开始加密聊天吧。",
    "name": "Alice",
    "nostrIdentityKey": "abc123...",
    "signalIdentityKey": "05def456...",
    "firstInbox": "ephemeral-nostr-pubkey-hex",
    "deviceId": "device-uuid",
    "signalSignedPrekeyId": 1,
    "signalSignedPrekey": "hex...",
    "signalSignedPrekeySignature": "hex...",
    "signalOneTimePrekeyId": 1,
    "signalOneTimePrekey": "hex...",
    "signalKyberPrekeyId": 1,
    "signalKyberPrekey": "hex...",
    "signalKyberPrekeySignature": "hex...",
    "globalSign": "schnorr-sig-hex",
    "time": 1700000000,
    "version": 2
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `message` | `string?` | 否 | 可选的问候语 |
| `name` | `string` | 是 | 显示名称 |
| `nostrIdentityKey` | `string` | 是 | 发送者的 Nostr secp256k1 公钥（hex） |
| `signalIdentityKey` | `string` | 是 | 发送者的 Signal Curve25519 身份公钥（hex，33 字节） |
| `firstInbox` | `string` | 是 | 临时 Nostr 公钥，用于首消息投递（非 Signal 密钥） |
| `deviceId` | `string` | 是 | 设备 ID，用于多设备场景区分 |
| `signalSignedPrekeyId` | `int` | 是 | 签名预密钥 ID |
| `signalSignedPrekey` | `string` | 是 | 签名预密钥（Curve25519，hex） |
| `signalSignedPrekeySignature` | `string` | 是 | 签名预密钥的 XEdDSA 签名 |
| `signalOneTimePrekeyId` | `int` | 是 | 一次性预密钥 ID |
| `signalOneTimePrekey` | `string` | 是 | 一次性预密钥（Curve25519，hex） |
| `signalKyberPrekeyId` | `int` | 是 | Kyber KEM 预密钥 ID |
| `signalKyberPrekey` | `string` | 是 | Kyber KEM 公钥（ML-KEM 1024，hex） |
| `signalKyberPrekeySignature` | `string` | 是 | Kyber 预密钥的 XEdDSA 签名 |
| `globalSign` | `string` | 是 | Schnorr 签名：`sign("Keychat-{nostrIdentityKey}-{signalIdentityKey}-{time}")` |
| `time` | `int?` | 否 | Unix 时间戳 |
| `version` | `int` | 是 | 协议版本，必须为 `2` |
| `relay` | `string?` | 否 | 首选中继 URL |
| `avatar` | `string?` | 否 | 头像 URL |
| `lightning` | `string?` | 否 | Lightning 地址 |

> **v1 → v2 字段映射**：`pubkey` → `nostrIdentityKey`，`curve25519PkHex` → `signalIdentityKey`，`onetimekey` → `firstInbox`，`prekeyId`/`prekeyPubkey` → `signalOneTimePrekeyId`/`signalOneTimePrekey`。Kyber 字段是 v2 新增的。

#### KCFriendApprovePayload / KCFriendRejectPayload

```json
{ "requestId": "fr-uuid-001", "message": "很高兴认识你！" }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `requestId` | `string` | 是 | 原始 friendRequest 消息的 `KCMessage.id` |
| `message` | `string?` | 否 | 可选文本 |

#### KCCashuPayload

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `mint` | `string` | 是 | Cashu mint URL |
| `token` | `string` | 是 | Cashu token 字符串 |
| `amount` | `int` | 是 | 金额（聪） |
| `unit` | `string?` | 否 | 货币单位 |
| `memo` | `string?` | 否 | 备注 |
| `message` | `string?` | 否 | 可选文本 |

#### KCLightningPayload

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `invoice` | `string` | 是 | BOLT-11 Lightning invoice |
| `amount` | `int` | 是 | 金额（聪） |
| `mint` | `string?` | 否 | 关联的 Cashu mint URL |
| `hash` | `string?` | 否 | Payment hash（hex） |
| `message` | `string?` | 否 | 可选文本 |

### 4.6 信封元数据字段

#### ReplyTo

引用另一条消息作为回复。使用双 ID 查找机制，确保群内跨成员兼容。

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `targetId` | `string?` | 否 | 被回复消息的 `KCMessage.id`（跨群成员可靠） |
| `targetEventId` | `string?` | 否 | 被回复消息的 Nostr event ID（本地回退） |
| `content` | `string` | 是 | 引用内容预览 |
| `userId` | `string?` | 否 | 原作者公钥 |
| `userName` | `string?` | 否 | 原作者显示名称 |

**查找顺序**：先按 `targetId` 匹配，未命中则回退到 `targetEventId`。

**为什么需要双 ID**：在 Signal 群组中，同一条消息对每个成员产生不同的 Nostr event ID（逐成员加密），但共享同一个 `KCMessage.id`。

#### SignalPrekeyAuth

Signal PrekeyMessage 上的身份绑定，在会话建立后的首条消息上携带。这是独立类型——**不是** KCFriendRequestPayload（后者携带完整的预密钥包用于密钥交换）。

| 字段 | 类型 | 说明 |
|------|------|------|
| `nostrId` | `string` | 发送者的 secp256k1 Nostr 公钥 |
| `signalId` | `string` | 发送者的 Curve25519 Signal 公钥 |
| `time` | `int` | Unix 时间戳（防重放） |
| `name` | `string` | 显示名称 |
| `sig` | `string` | 对 `"Keychat-{nostrId}-{signalId}-{time}"` 的 Schnorr 签名 |
| `avatar` | `string?` | 头像 URL |
| `lightning` | `string?` | Lightning 地址 |

**出现时机**：
- Bob 接受好友请求后发送首条消息（PrekeyMessage）
- Alice 扫描二维码后发送首条消息（PrekeyMessage）
- 会话重置后（新 PrekeyMessage）

接收方验证 Schnorr 签名后，更新本地存储的对方用户信息。

#### threadId

将消息归属到子会话。根消息是 `KCMessage.id` 等于 `threadId` 的那条消息。Thread 是扁平的（所有消息指向根，而非上一条回复）。

`threadId` 和 `replyTo` 可共存：`threadId` 表示属于哪个 thread，`replyTo` 表示在 thread 内引用哪条消息。

#### ForwardFrom

标记消息为转发。`senderName`、`senderId`、`originalTime`——全部可选，支持匿名转发。

### 4.7 前向兼容

| 场景 | 行为 |
|------|------|
| 已知 `kind` | 正常解析，忽略 `fallback` |
| 未知 `kind` + 有 `fallback` | 以纯文本显示 `fallback` |
| 未知 `kind` + 无 `fallback` | 显示默认提示："当前版本不支持此消息，请升级 Keychat" |

**发送端规则**：当使用初始 v2 规范未定义的 `kind` 时，**应当**填充 `fallback`。

### 4.8 版本协商

- **1:1**：`friendRequest.version` 携带发送者的协议版本，存储为 `Room.peerVersion`。
- **Signal 群组**：邀请中的 `RoomProfile` 携带版本信息。
- **MLS 群组**：`GroupExtension` 包含 `version` 字段。

**解析逻辑**：
```
tryParseMessage(str):
  json = JSON.parse(str)
  if json.v == 2 → KCMessage.fromJson(json)
  else → null（作为纯文本处理）
```

---

## 5. 加密层

### 5.1 Signal Protocol + PQXDH

Keychat 的加密层构建在两个成熟的密码学库之上：

- **libsignal** — Signal 官方的 Rust 实现，提供 PQXDH 密钥协商、Double Ratchet 和会话管理。
- **OpenMLS** — MLS（消息层安全）标准（RFC 9420）的开源 Rust 实现，提供可扩展的群组加密。

Keychat 协议的实现库 **libkeychat** 构建在这两个库之上，在其上增加了 Nostr 身份层、中继传输、地址轮换和 ecash 邮票集成。

Keychat 使用 Signal Protocol 进行 1:1 和小群组加密，初始密钥协商从 X3DH 升级为 **PQXDH**（后量子扩展 Diffie-Hellman）。

#### PQXDH 参数

| 参数 | 值 |
|------|------|
| curve | Curve25519 |
| hash | SHA-512 |
| pqkem | ML-KEM 1024（CRYSTALS-Kyber-1024） |
| info | "Keychat" |

#### PQXDH 的变化

PQXDH 在 X3DH 的基础上增加了后量子 KEM（密钥封装机制）。预密钥包现在除了 Curve25519 密钥外，还包含一个 **Kyber KEM 公钥**。

会话建立时：
1. Alice 执行标准的 ECDH 计算（DH1、DH2、DH3，可选 DH4）
2. Alice **同时**使用 Bob 的 Kyber 公钥封装一个共享密钥：`(CT, SS) = PQKEM-ENC(KyberPrekey)`
3. 最终会话密钥结合两者：`SK = KDF(DH1 || DH2 || DH3 [|| DH4] || SS)`
4. Alice 将 KEM 密文 `CT` 连同初始消息一起发送

这提供**混合安全性**：只要经典（ECDH）或后量子（Kyber）假设之一成立，会话就是安全的。量子计算机必须同时破解两者才能获取会话密钥。

#### PQXDH 之后

会话建立后，Double Ratchet 的运行与标准 Signal Protocol 完全相同。后量子保护适用于初始密钥协商；后续棘轮步骤使用 Curve25519 ECDH。未来的 Signal Protocol 版本可能增加后量子棘轮。

### 5.2 MLS（消息层安全）

大群组使用 MLS（RFC 9420）进行可扩展的群组加密，采用棘轮树结构。详见 §11。

### 5.3 NIP-17 Gift Wrap

当不存在加密会话时（好友请求）使用。提供 NIP-44 加密和元数据保护。详见 §3.3 模式二。

---

## 6. 添加联系人（好友请求）

Alice 想添加 Bob。她只知道 Bob 的 npub。

### 6.1 前提条件

- Alice 的 Nostr 身份（secp256k1 密钥对）
- Bob 的 Nostr 公钥（hex）或 npub

#### 公钥格式标准化

所有接受 Nostr 公钥的公共 API 入口**必须**同时支持两种格式：
- **npub**（bech32 编码，如 `npub1cqpv...558u`）
- **hex**（64 字符，如 `c002c688...d033`）

实现**必须**在内部统一转换为 hex 格式。适用于：
- 添加联系人（好友请求目标）
- 群组邀请（被邀请者身份）
- 任何接受对端标识符的用户面向 API

### 6.2 逐步流程

```
1. 为此对端生成 Signal 身份：
   (signal_private, signal_public) = generate_signal_ids()
   signalIdentityKey = hex(signal_public)  // 33 字节 → 66 个 hex 字符

2. 生成签名预密钥：
   (signedId, signedPublic, signedSignature, signedRecord) =
     generate_signed_key(signal_private)

3. 生成一次性预密钥：
   (prekeyId, prekeyPublic, prekeyRecord) = generate_prekey()

4. 生成 Kyber KEM 预密钥（PQXDH）：
   (kyberPrekeyId, kyberPublic, kyberSignature, kyberRecord) =
     generate_kyber_prekey(signal_private)

5. 生成 firstInbox（用于首消息接收的临时 Nostr 密钥对）：
   firstInbox_pair = generate_secp256k1()
   firstInbox = firstInbox_pair.pubkey  // hex

6. 构建 KCFriendRequestPayload：
   {
     "name": "<alice_显示名>",
     "nostrIdentityKey": "<alice_nostr_公钥_hex>",
     "signalIdentityKey": "<signal_公钥_hex>",
     "firstInbox": "<firstInbox_公钥_hex>",
     "deviceId": "<设备_uuid>",
     "signalSignedPrekeyId": <signedId>,
     "signalSignedPrekey": "<hex(signedPublic)>",
     "signalSignedPrekeySignature": "<hex(signedSignature)>",
     "signalOneTimePrekeyId": <prekeyId>,
     "signalOneTimePrekey": "<hex(prekeyPublic)>",
     "signalKyberPrekeyId": <kyberPrekeyId>,
     "signalKyberPrekey": "<hex(kyberPublic)>",
     "signalKyberPrekeySignature": "<hex(kyberSignature)>",
     "globalSign": "<schnorr_签名>",
     "time": <unix_时间戳>,
     "version": 2
   }

7. 计算 globalSign（Schnorr 签名）：
   message = "Keychat-<nostrIdentityKey>-<signalIdentityKey>-<time>"
   globalSign = schnorr_sign(alice_nostr_私钥, sha256(message))

8. 构建 KCMessage：
   {
     "v": 2,
     "id": "<uuid-v4>",
     "kind": "friendRequest",
     "friendRequest": <步骤6的载荷>
   }

9. 通过 NIP-17 Gift Wrap 发送（kind:1059，模式二）：
   ephemeral_wrapper = generate_ephemeral_keypair()  // 随机密钥对，用于外层 Gift Wrap
   gift_wrap = create_gift_wrap(
     wrapper_keys = ephemeral_wrapper,        // 外层：隐藏 Alice
     sender_keys = alice_nostr_密钥对,       // Seal 层：证明 Alice 的身份
     receiver_pubkey = bob_nostr_公钥,
     content = kcmessage_json,
     timestamp_tweaked = false
   )
   发布到中继
   // 外层 Gift Wrap pubkey = 临时密钥（匿名）
   // Seal pubkey = Alice 的真实身份（加密，只有 Bob 能看到）

   // Keychat 所有 kind 1059 事件均使用真实时间戳——不做偏移。

10. 开始监听：
    - alice_nostr_pubkey（始终监听）
    - firstInbox（等待 Bob 的首条回复）
```

### 6.3 关键：发送好友请求后的监听地址

发送好友请求后，Alice **必须**订阅以下地址的 kind 1059 事件：

1. **firstInbox** — Bob 的首条回复（同意/拒绝及可能的后续消息）将发送到这里
2. **棘轮派生地址** — 棘轮激活后，后续消息到达派生地址（§9）

如果 Alice 未监听 `firstInbox`，将完全错过 Bob 的回复。

---

## 7. 接受好友请求

Bob 收到一个发往其公钥的 kind 1059 事件。

### 7.1 解包 Gift Wrap

```
1. 用 NIP-44 解密 kind:1059 content，使用 bob_私钥 + event.pubkey
   → seal_json（kind 13）

2. 验证 seal 事件签名

3. 用 NIP-44 解密 seal content，使用 bob_私钥 + seal.pubkey
   → rumor_json（kind 14，未签名）

4. 解析 rumor.content 为 KCMessage
   检查 v == 2 且 kind == "friendRequest"

5. 提取 friendRequest 载荷
```

### 7.2 验证身份

```
message = "Keychat-<friendRequest.nostrIdentityKey>-<friendRequest.signalIdentityKey>-<friendRequest.time>"
verify_schnorr(friendRequest.nostrIdentityKey, friendRequest.globalSign, sha256(message))
```

验证失败则中止。

### 7.3 建立 Signal 会话（PQXDH）

```
process_prekey_bundle(
  my_keypair = bob_signal_密钥对,
  remote_address = {
    name: friendRequest.signalIdentityKey,
    device_id: bob_identity_id
  },
  identity_key = friendRequest.signalIdentityKey,
  signed_prekey_id = friendRequest.signalSignedPrekeyId,
  signed_prekey = friendRequest.signalSignedPrekey,
  signed_prekey_signature = friendRequest.signalSignedPrekeySignature,
  one_time_prekey_id = friendRequest.signalOneTimePrekeyId,
  one_time_prekey = friendRequest.signalOneTimePrekey,
  kyber_prekey_id = friendRequest.signalKyberPrekeyId,
  kyber_prekey = friendRequest.signalKyberPrekey,
  kyber_prekey_signature = friendRequest.signalKyberPrekeySignature
)
```

PQXDH 握手内部：
1. 使用 Alice 的 Curve25519 密钥执行 ECDH 计算
2. 使用 Alice 的 Kyber 公钥封装共享密钥
3. 通过 HKDF 结合两者派生会话密钥

### 7.4 自动回复（如果同意）

如果 Bob 接受，他通过 Signal 加密发送 `friendApprove` 消息。这是 Bob 发给 Alice 的首条 Signal 消息——一个 **PrekeyMessage**（棘轮刚初始化）。

回复发送到 Alice 的 **firstInbox** 地址。

```json
{
  "v": 2,
  "kind": "friendApprove",
  "friendApprove": {
    "requestId": "<原始 friendRequest 的 id>"
  },
  "signalPrekeyAuth": {
    "nostrId": "<bob_nostr_公钥>",
    "signalId": "<bob_signal_公钥>",
    "name": "Bob",
    "time": 1700000000,
    "sig": "<schnorr_签名>"
  }
}
```

**一条消息，三个作用**：好友同意 + 身份绑定 + Signal 会话建立。

---

## 8. Signal 加密 1:1 聊天

Signal 会话建立后，所有消息使用 kind 1059 事件（模式一）配合 Signal Protocol 加密。

### 8.1 发送消息

```
1. 构建 KCMessage：
   { "v": 2, "kind": "text", "text": { "content": "Hello Bob!" } }

2. 确定发送地址（投递目标）：
   session = get_session(my_keypair, peer_signal_pubkey, device_id)
   bob_address = session.bobAddress

   如果 bob_address 以 "05" 开头（原始 Signal 身份密钥，棘轮尚未建立）：
     如果 room.peerFirstInbox 存在 → to_address = peerFirstInbox
     否则 → to_address = peer_nostr_pubkey
   否则：
     to_address = derive_nostr_address(bob_address)

3. 用 Signal 加密：
   (ciphertext, new_receiving_addr, msg_key_hash, alice_addrs) =
     encrypt_signal(my_keypair, kcmessage_json, remote_address)

4. 如果返回了 new_receiving_addr：
   derived_pubkey = derive_nostr_address(new_receiving_addr)
   在中继上订阅此地址（这是我的新接收地址）
   存入数据库

5. 生成临时发送者密钥对：
   sender = generate_ephemeral_keypair()  // 随机，一次性使用

6. 构建 kind 1059 事件：
   {
     "kind": 1059,
     "pubkey": sender.pubkey,           // 临时密钥，不是真实 pubkey
     "content": base64_encode(ciphertext),
     "tags": [["p", to_address]],
     "created_at": unix_now(),          // 真实时间戳，不做偏移
     "id": compute_event_id(...),
     "sig": sign(sender.privkey, ...)
   }

7. 发布到中继
```

### 8.2 接收消息

```
1. 事件到达我的某个监听地址（kind 1059，模式一）

2. 解码：ciphertext = base64_decode(event.content)

3. 检查是否为 PrekeyMessage：
   is_prekey = PreKeySignalMessage::try_from(ciphertext).is_ok()

   ⚠️ 不要用 ciphertext[0] == 3 检测。Signal 消息是 protobuf 编码的，
   第一个字节是字段标记，不是类型指示符。

4. 如果是 PrekeyMessage：
   (signal_identity, signed_prekey_id) =
     parse_identity_from_prekey_signal_message(ciphertext)
   用 signed_prekey_id 找到对应的 Signal 身份
   以 is_prekey=true 解密
   从解密后的 KCMessage 解析 signalPrekeyAuth，验证签名

5. 如果是普通消息：
   以 is_prekey=false 解密

6. 解密后，更新此对端的发送地址：
   会话的 bobAddress 现在指向对端的新接收地址。
   下次发送时使用此更新后的地址（见步骤 2）。

7. 解析解密后的明文：
   尝试 JSON 解析为 KCMessage（检查 v == 2）→ 按 kind 路由
   如果不是有效的 KCMessage JSON → 作为纯文本处理
```

### 8.3 何时使用 firstInbox

`firstInbox` 是临时收信地址，不一定是一次性的。对方可能向它发送多条消息（同意 + 后续消息），然后棘轮地址才接管。

```
发送好友请求：
  → peerFirstInbox = alice.firstInbox（来自 friendRequest）

对方发送同意 + 可能的后续消息 → 都发到 firstInbox

收到发往棘轮派生地址的首条消息：
  → 清除 peerFirstInbox（棘轮已激活）
  → 棘轮地址处理所有后续路由
```

---

## 9. 接收地址轮换

这是 Keychat 最显著的特性。每次 DH 棘轮步骤生成一个新的 Nostr 接收地址，提供**消息不可关联性**。

### 9.1 地址派生

Signal Double Ratchet 交换 DH 公钥。Keychat 从每个棘轮密钥对派生一个 Nostr secp256k1 公钥：

```
输入：
  private_key：Curve25519 私钥（32 字节）
  public_key： Curve25519 公钥（33 字节）

1. ECDH：  shared_secret = private_key.calculate_agreement(public_key)

2. 填充：  seed = [0xFF; 32] || shared_secret

3. 哈希：  hash = SHA256(seed)[0..32]  // 前 32 字节

4. 派生：  secret_key = secp256k1_secret_key(hash)

5. 结果：  nostr_address = x_only_public_key(secret_key).hex()
```

这是一个跨曲线的单向映射：Curve25519 棘轮状态 → secp256k1 Nostr 地址。

### 9.2 何时轮换

- **加密后**：`new_receiving_addr` 是你的新地址。在中继上订阅它。
- **解密后**：`session.bobAddress` 更新为对端的新地址。下次发送时用它作为目标。
- **轮换是方向性的**：连续发送 5 条消息不会轮换地址。DH 棘轮仅在**方向改变**时前进（先收后发，或先发后收）。

### 9.3 滑动窗口

为每个对端维护接收地址的滑动窗口（推荐：2–3 个）：

```
addresses = [addr_n-1, addr_n]  // 同时监听两个
// 当 addr_n+1 到达 → 丢弃 addr_n-1，添加 addr_n+1
```

旧地址从中继订阅中移除。这限制了每个对端的地址数量，同时容忍轻微的消息乱序。

### 9.4 发送地址解析

发送时，按以下优先级解析目标地址：

```
1. session.bobAddress 存在且不是原始 Signal 身份密钥（0x05 前缀，66 字符）？
   → derive_nostr_address(bobAddress) = 投递目标

2. bobAddress 是原始 Signal 身份密钥或不存在？
   → room.peerFirstInbox 存在？使用它（首消息给对端）
   → 否则：room.toMainPubkey（对端的 Nostr 身份公钥）
```

使用 `peerFirstInbox` 时，消息将是带 `signalPrekeyAuth` 的 PrekeyMessage。

### 9.5 生命周期示例

```
Alice                                              Bob
  |                                                  |
  |-- friendRequest（NIP-17 → Bob 的 npub）---------> |
  |                                                  |
  | <-- friendApprove（Signal PrekeyMsg → firstInbox）|
  |    [Bob 棘轮初始化，注册 recvAddr_B1]             |
  |                                                  |
  |-- msg1（→ recvAddr_B1）---------------------------> |
  |    [Alice 棘轮步进，注册 recvAddr_A1]             |
  |    [Alice 清除 peerFirstInbox]                    |
  |                                                  |
  | <-------------------------------- msg2（→ recvAddr_A1）
  |                              [Bob 棘轮步进]       |
  |                              [Bob 注册 recvAddr_B2]
  |                              [Bob 丢弃 recvAddr_B1]
  |                                                  |
  |-- msg3（→ recvAddr_B2）---------------------------> |
  |    ...                                           |
```

---

## 10. Signal 群组（sendAll）

小群组（推荐 < 50 成员）使用 Signal Protocol 逐成员加密。

### 10.1 工作原理

没有共享群密钥。发送者使用各自的 1:1 Signal 会话，为每个群成员单独加密消息：

```
发送者构建 KCMessage：
  { "v": 2, "id": "msg-uuid", "kind": "text", "groupId": "group-pubkey", "text": {...} }

对每个成员（并行）：
  encrypt_signal(member_session, kcmessage_json)
  → 作为 kind 1059 发布到成员的接收地址
```

所有成员收到相同的 `KCMessage.id`，实现去重和一致的回复引用。

### 10.2 发送者认证

Signal Protocol 本身就认证了发送者——每个成员通过已知的 1:1 会话解密。不需要额外的应用层签名。

管理员操作（`signalGroupMemberRemoved`、`signalGroupDissolve` 等）通过检查发送者的 `RoomMember.isAdmin` 验证。

### 10.3 群管理

| 操作 | KCMessage Kind |
|------|---------------|
| 邀请 | `signalGroupInvite`（包含带成员列表的 RoomProfile） |
| 移除成员 | `signalGroupMemberRemoved` |
| 成员退群 | `signalGroupSelfLeave` |
| 解散 | `signalGroupDissolve` |
| 改群名 | `signalGroupNameChanged` |
| 改昵称 | `signalGroupNicknameChanged` |

---

## 11. MLS 群组

大群组使用 MLS（RFC 9420）进行可扩展的加密。

### 11.1 核心概念

- **棘轮树**：基于树的密钥派生。成员持有叶子密钥；根节点派生群加密密钥。
- **纪元（Epoch）**：每次 Commit 推进纪元，轮换群密钥。
- **KeyPackage**：成员的公钥包，作为 kind 10443 Nostr 事件发布。
- **Welcome**：新成员加入群组的邀请数据。

### 11.2 接收地址（mlsTempInbox）

每个 MLS 群成员从 MLS export secret 计算共享接收地址：

```
replaceListenPubkey(room):
  new_inbox = mls.getListenKeyFromExportSecret(nostrId, groupId)
  // 确定性派生——同纪元内所有成员计算结果一致

  如果 new_inbox == room.mlsTempInbox → 无变化
  否则：
    取消订阅(旧 mlsTempInbox)
    room.mlsTempInbox = new_inbox
    订阅(new_inbox)
```

此地址**在每次 Commit 后轮换**（添加/移除成员、密钥更新等）。处理 Commit 后，所有成员必须调用 `replaceListenPubkey()`。

### 11.3 入群流程

```
管理员                                          新成员
  |                                                |
  +-- mls.addMembers(keyPackages)                  |
  +-- mls.selfCommit()                             |
  +-- replaceListenPubkey()                        |
  +-- 广播 Commit（kind 1059，模式一）              |
  +-- 发送 mlsGroupInvite（Signal 或 NIP-17）----> |
  |                                                +-- mls.joinMlsGroup(welcome)
  |                                                +-- replaceListenPubkey()
  |                                                +-- 发送问候（selfUpdate Commit）
  | <-- selfUpdate Commit（kind 1059）-------------|
  +-- 处理 update，replaceListenPubkey()           |
```

### 11.4 发送消息

```
1. 构建 KCMessage：
   { "v": 2, "kind": "text", "groupId": "...", "text": {...} }

2. 加密：mls.createMessage(nostrId, groupId, kcmessage_json)

3. 生成临时发送者密钥对

4. 发布 kind 1059 到 room.mlsTempInbox（模式一）
```

### 11.5 MLS 管理 vs. KCMessage

MLS 有原生的 Commit 管理机制。这些操作**不**表示为 KCMessage kind：

| 操作 | 机制 | 传输方式 |
|------|------|---------|
| 添加成员 | `mls.addMembers()` → Commit + Welcome | Commit：广播（kind 1059）；Welcome：通过 `mlsGroupInvite` |
| 移除成员 | `mls.removeMembers()` → Commit | kind 1059 |
| 主动退群 | `mls.selfUpdate(status: "removed")` → Commit | kind 1059 |
| 解散 | `mls.updateGroupContextExtensions(status: "dissolved")` → Commit | kind 1059 |
| 改群名 | `mls.updateGroupContextExtensions(name: ...)` → Commit | kind 1059 |
| 密钥更新 | `mls.selfUpdate()` → Commit | kind 1059 |

---

## 12. 媒体与文件传输

### 12.1 上传

文件在客户端加密后上传到文件服务器（S3 兼容或 Blossom）：

```
1. 生成随机 AES-256 密钥 + IV
2. 用 AES-256-CTR + PKCS7 填充加密文件
3. 计算加密文件的 SHA256 哈希
4. 上传到文件服务器 → 获取访问 URL
5. 发送 KCMessage kind "files"，包含 url、key、iv、hash
```

接收方下载加密文件并在本地解密。

### 12.2 消息格式

```json
{
  "v": 2,
  "kind": "files",
  "files": {
    "items": [{
      "category": "image",
      "url": "https://files.example.com/abc123",
      "type": "image/jpeg",
      "size": 245760,
      "key": "<aes-key-hex>",
      "iv": "<iv-hex>",
      "hash": "<sha256-hex>"
    }]
  }
}
```

### 12.3 语音消息

语音录音使用 `category: "voice"`，附带额外字段：
- `audioDuration`：时长（秒）
- `amplitudeSamples`：波形数据，用于内联渲染

---

## 13. Ecash 邮票

Keychat 使用 Cashu ecash 作为反垃圾的"邮票"用于消息投递。

### 13.1 工作原理

```
1. 发送者从 Cashu mint 获取 ecash token
2. 发送者将 token 作为第三个元素附加到 Nostr EVENT 消息：
   ["EVENT", <event_json>, <ecash_token_字符串>]
   （这是 Keychat 中继协议扩展——标准 NIP-01 只有两个元素）
3. 中继收到事件，兑换 ecash 邮票
4. 中继存储并广播标准 Nostr 事件（不含 token）
```

ecash 邮票对接收者透明——只有中继看到并收取它。这提供了无需账户或身份的经济反垃圾机制。

### 13.2 Token 格式

`<ecash_token_字符串>` 是 Cashu token（以 `cashuA` 开头的 base64 字符串）。

---

## 14. 密码学原语参考

### 14.1 密钥类型

| 密钥 | 曲线/算法 | 大小 | 用途 |
|------|----------|------|------|
| Nostr 身份 | secp256k1 | 32 字节私钥，32 字节 x-only 公钥 | 身份、签名、NIP-44 |
| Signal 身份 | Curve25519 | 32 字节私钥，33 字节公钥 | Signal 会话身份 |
| 签名预密钥 | Curve25519 | 33 字节公钥 | PQXDH 握手 |
| 一次性预密钥 | Curve25519 | 33 字节公钥 | PQXDH 握手（一次性使用） |
| Kyber 预密钥 | ML-KEM 1024 | ~1568 字节公钥 | PQXDH 后量子 KEM |
| firstInbox | secp256k1 | 32 字节 x-only 公钥 | 临时 Nostr 接收地址 |
| 棘轮派生地址 | secp256k1 | 32 字节 x-only 公钥 | 每条消息的 Nostr 接收地址 |

### 14.2 加密算法

| 算法 | 用途 |
|------|------|
| **NIP-44**（XChaCha20 + HMAC-SHA256） | Gift Wrap 加密 |
| **Signal Protocol**（PQXDH + Double Ratchet，AES-256-CBC + HMAC-SHA256） | 1:1 和小群组加密 |
| **ML-KEM 1024**（CRYSTALS-Kyber） | PQXDH 中的后量子密钥封装 |
| **MLS**（TreeKEM + AEAD） | 大群组加密 |
| **AES-256-CTR** | 媒体文件加密 |

### 14.3 签名

| 算法 | 用途 |
|------|------|
| **Schnorr**（BIP-340） | friendRequest 中的 `globalSign`，SignalPrekeyAuth 中的 `sig` |
| **XEdDSA** | Signal 预密钥签名（签名预密钥、Kyber 预密钥） |
| **Ed25519** | Nostr 事件签名 |

### 14.4 PQXDH 密钥协商

```
Alice（发起方）                           Bob（响应方）

持有：IK_A（身份密钥）                    持有：IK_B（身份密钥）
生成：EK_A（临时密钥）                    已发布：SPK_B（签名预密钥）
                                                  OPK_B（一次性预密钥，可选）
                                                  PQPK_B（Kyber 预密钥）

Alice 计算：
  DH1 = DH(IK_A, SPK_B)
  DH2 = DH(EK_A, IK_B)
  DH3 = DH(EK_A, SPK_B)
  DH4 = DH(EK_A, OPK_B)                  // 如果 OPK_B 可用
  (CT, SS) = PQKEM-ENC(PQPK_B)           // Kyber 封装

  SK = KDF(DH1 || DH2 || DH3 [|| DH4] || SS)

Alice 发送给 Bob：
  - IK_A、EK_A、CT
  - 密钥标识符（使用了哪些预密钥）
  - 初始密文（用 SK 加密）

Bob 计算：
  用私钥计算相同的 DH 值
  SS = PQKEM-DEC(PQPK_B, CT)             // Kyber 解封装
  SK = KDF(DH1 || DH2 || DH3 [|| DH4] || SS)
```

### 14.5 棘轮地址派生

```
derive_receiving_address(private_key: [u8; 32], public_key: [u8; 33]) -> String:
  // 输入：Curve25519 棘轮私钥 + 对端的棘轮公钥
  dh   = private_key.calculate_agreement(public_key)
  seed = [0xFF; 32] || dh
  hash = SHA256(seed)[0..32]
  sk   = secp256k1_secret_key(hash)
  return x_only_public_key(sk).hex()
```

---

## 15. 实现检查清单

### 阶段一：身份与传输
- [ ] 从 BIP-39 助记词生成/导入 Nostr 身份
- [ ] 通过 WebSocket 连接 Nostr 中继
- [ ] 按公钥过滤器订阅事件（kind 1059）
- [ ] 发布事件到中继（可选附带 ecash 邮票）
- [ ] NIP-44 加密/解密（用于 Gift Wrap）
- [ ] NIP-17 三层包装/解包（kind 1059 → seal → rumor）

### 阶段二：好友请求（PQXDH）
- [ ] 生成 Signal 身份（Curve25519）
- [ ] 生成签名预密钥 + 一次性预密钥
- [ ] 生成 Kyber KEM 预密钥（ML-KEM 1024）
- [ ] 构建包含所有字段的 KCFriendRequestPayload
- [ ] 计算 Schnorr `globalSign`
- [ ] 作为 NIP-17 Gift Wrap 发送好友请求
- [ ] 监听 firstInbox + signalIdentityKey 派生地址

### 阶段三：接受好友请求
- [ ] 解包 kind 1059 Gift Wrap（三层解密）
- [ ] 解析 KCMessage v2 `kind: "friendRequest"`
- [ ] 验证 Schnorr `globalSign`
- [ ] 处理 PQXDH 预密钥包（EC + Kyber 密钥）
- [ ] 发送带 `signalPrekeyAuth` 的 `friendApprove`（首条 PrekeyMessage）

### 阶段四：Signal 聊天
- [ ] 用 Signal Protocol 加密消息
- [ ] 作为 kind 1059 发送，使用临时发送者 + base64 内容
- [ ] 接收并解密 kind 1059 消息（模式一）
- [ ] 通过 `PreKeySignalMessage::try_from()` 检测 PrekeyMessage
- [ ] 解析并验证 `signalPrekeyAuth`
- [ ] KCMessage v2 解析（v==2，基于 kind 的路由）

### 阶段五：地址轮换
- [ ] 加密后：派生新接收地址，在中继上订阅
- [ ] 解密后：从 session.bobAddress 更新发送地址
- [ ] 接收地址滑动窗口（每对端 2–3 个）
- [ ] 从订阅中清理旧地址
- [ ] 首次棘轮交换后清除 peerFirstInbox

### 阶段六：群组
- [ ] Signal 群组：逐成员加密 + 发送（sendAll）
- [ ] Signal 群组：管理 kind（邀请、移除、退群、解散、改名）
- [ ] MLS：发布 KeyPackage（kind 10443）
- [ ] MLS：处理 Welcome（加入群组）
- [ ] MLS：应用消息收发（kind 1059）
- [ ] MLS：Commit 处理 + mlsTempInbox 轮换
- [ ] MLS：加入后重新发布 KeyPackage

### 阶段七：媒体与支付
- [ ] 文件加密（AES-256-CTR）+ 上传
- [ ] 带加密元数据的 KCFilesPayload
- [ ] 带波形数据的语音消息
- [ ] Cashu ecash token 收发
- [ ] Lightning invoice 收发

### 阶段八：健壮性
- [ ] 持久化 Signal 会话状态（棘轮密钥在重启后存活）
- [ ] 持久化收发地址到数据库
- [ ] 事件去重（跟踪已处理的 event ID）
- [ ] 中继发布失败的重试逻辑
- [ ] 处理会话重置（新好友请求）
- [ ] Ecash 邮票附加用于中继投递

---

## 附录 A：Room 模型

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | `int` | 自增主键 |
| `toMainPubkey` | `string` | 对端的 Nostr 公钥（1:1）或群公钥（群聊） |
| `identityId` | `int` | 所有者的 Nostr 身份 |
| `type` | `RoomType` | `common`（1:1）或 `group` |
| `groupType` | `GroupType?` | `sendAll`（Signal 群组）、`mls`（MLS 群组） |
| `status` | `RoomStatus` | 生命周期状态（见下） |
| `encryptMode` | `EncryptMode` | `signal`、`nip17`、`mls` |
| `peerFirstInbox` | `string?` | 对端的首消息接收公钥（棘轮交换后清除） |
| `mlsTempInbox` | `string?` | MLS 群接收公钥（每纪元轮换） |
| `version` | `int` | 防重放时间戳/纪元跟踪 |
| `peerVersion` | `int?` | 对端的 KCMessage 协议版本 |

### RoomStatus

| 值 | 说明 |
|------|------|
| `init` | 已创建，尚未激活 |
| `requesting` | 已发送好友请求，等待回复 |
| `approving` | 已收到好友请求，等待用户同意 |
| `enabled` | 活跃会话已建立 |
| `rejected` | 好友请求被拒绝 |
| `dissolved` | 群组已被管理员解散 |
| `removedFromGroup` | 被管理员从群组中移除 |

---

## 附录 B：v1 → v2 迁移摘要

| 方面 | v1 | v2 |
|------|----|----|
| 消息格式 | `{"c":"signal","type":100,"msg":"...","name":"..."}` | `{"v":2,"kind":"text","text":{"content":"..."}}` |
| 传输 kind | kind:4（Signal）、kind:1059（NIP-17）、kind:444（MLS Welcome） | 全部使用 kind:1059 |
| 密钥协商 | X3DH | PQXDH（X3DH + Kyber KEM） |
| 好友请求字段：身份 | `curve25519PkHex` | `signalIdentityKey` |
| 好友请求字段：收件箱 | `onetimekey` | `firstInbox` |
| 好友请求字段：Nostr 密钥 | `pubkey` | `nostrIdentityKey` |
| 身份绑定 | `PrekeyMessageModel`（嵌入 `name` 字段） | `signalPrekeyAuth`（信封元数据字段） |
| 消息类型 | 数字（`type: 100, 101, 104, ...`） | 字符串枚举（`"text"`、`"friendRequest"`、...） |
| 协议指示符 | `"c": "signal"` / `"nip04"` / `"group"` | 已移除（由外部处理） |

---

## 附录 C：常见陷阱

1. **所有消息使用 kind 1059** — v2 没有 kind:4。Signal 消息、MLS 消息和 NIP-17 Gift Wrap 都使用 kind 1059。接收端通过将 `p`-tag 与已知地址匹配来路由。

2. **模式一的内容是原始 base64，不是 NIP-44** — 对于 Signal/MLS 消息，kind 1059 事件的 content 就是 `base64(密文)`。不要在上面再加 NIP-44 加密。

3. **每条消息使用随机临时发送者** — 为每个出站事件生成新的 Nostr 密钥对。永远不要从真实 npub 发布。

4. **PrekeyMessage 检测：使用 `try_from()`，不要检查字节** — Signal 消息是 protobuf 编码的。`ciphertext[0]` 是字段标记，不是类型指示符。

5. **Signal 身份必须逐对端生成** — 为每个联系人生成新的 Curve25519 密钥对。跨对端共享会导致路由冲突。

6. **发送好友请求后监听 firstInbox** — 对端的首条回复发到你的 firstInbox。未订阅此地址意味着完全错过回复。

7. **永远不要删除 Signal 数据库** — 它包含棘轮状态。丢失它会永久销毁所有会话。

8. **地址轮换是方向性的** — 加密后的 `new_receiving_addr` 是你的地址。解密后的 `bobAddress` 是对端的地址。不要搞混。

9. **DH 棘轮仅在方向改变时前进** — 连续发送多条消息不会轮换地址。

10. **PQXDH Kyber 密钥是必须的** — v2 要求好友请求中包含 Kyber KEM 预密钥。实现必须生成和处理 ML-KEM 1024 密钥材料。

11. **所有 kind 1059 事件使用真实时间戳** — 与标准 NIP-17 不同，Keychat 不对任何 kind 1059 事件（包括 Gift Wrap）使用随机时间戳偏移。中继按 `since` 过滤——偏移后的时间戳可能导致事件不可见。

12. **mlsTempInbox 必须在每次 Commit 后轮换** — 处理 MLS Commit 后未调用 `replaceListenPubkey()` 将导致成员错过后续群消息。
