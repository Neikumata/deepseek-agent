# Sensitive Guard

敏感信息过滤 CLI 工具。在请求 LLM 之前自动检测和替换敏感信息（API Key、手机号、密码、身份证号等），LLM 返回后自动还原，确保大模型侧不接触真实敏感数据。检测规则可扩展，内置 Agent 自修正能力。

## 安装

```bash
cd deepseek-agents
uv venv
uv pip install -e .
```

## 配置

```bash
cp config.yaml.example config.yaml
```

编辑 `config.yaml`，设置 LLM API：

```yaml
agent:
  api_key: "sk-xxxx"           # 或 ${DEEPSEEK_API_KEY}
  api_base_url: "https://api.deepseek.com"
  model: "deepseek-chat"
```

规则列表在 `config.yaml` 的 `rules` 段，内置 10 条规则（API Key、手机号、密码、身份证、银行卡、邮箱、IP、JWT、Bearer Token、私钥），可按需启用/禁用或新增。

## 使用

### 检测敏感信息

```bash
# 直接检测文本
uv run sensitive-guard detect -t "我的手机号是13812345678"

# 从文件检测
uv run sensitive-guard detect -f config.yaml

# JSON 输出
uv run sensitive-guard detect -t "文字" --json
```

### 过滤替换

```bash
# 预览替换结果
uv run sensitive-guard filter -t "手机号13812345678" --dry-run

# 实际替换
uv run sensitive-guard filter -t "手机号13812345678"
# 输出: 手机号__PH_SENSITIVE_1__
```

### 完整链路：过滤 → LLM → 还原

```bash
# 单轮对话
uv run sensitive-guard chat "用 key: sk-abc123 查一下 13800001111 的账户"

# 多轮对话
uv run sensitive-guard chat "我的手机是13800138000" --session mychat
uv run sensitive-guard chat "刚才说的手机号是多少" --session mychat

# 对话后自动修正规则
uv run sensitive-guard chat "我的支付宝是alipay_account=test@123" --auto-correct

# 显示检测详情
uv run sensitive-guard chat "hello" --show-detection
```

LLM 只收到占位符版本（`__PH_SENSITIVE_N__`），回复后自动还原为真实内容。会话历史持久化到 `~/.sensitive_guard/sessions.json`，其中存的是占位符。

### Agent 自修正

当规则漏检时，调用 LLM 分析文本并建议新规则：

```bash
# 检测并自动修正（--auto-correct）
uv run sensitive-guard detect -t "我的支付宝是alipay_account=test@123" --auto-correct

# 独立分析命令
uv run sensitive-guard correct "我的企业微信 corpid 是 ww1234567890abcdef"
```

Agent 会输出建议的规则名、正则表达式和置信度，`--auto-correct` 自动将新规则写回 `config.yaml`。

### 查看映射

```bash
uv run sensitive-guard mappings
```

## 架构

```
用户输入
  → detector.detect()          # 正则匹配敏感信息
  → mapping.replace_all()      # 替换为 __PH_SENSITIVE_N__
  → GuardedLLMClient.chat()    # HTTP 请求 LLM
  → mapping.restore()          # 还原占位符
  → 输出真实内容
```

## 安全边界

- **`sessions.json`**: 只存占位符，泄露不可用
- **`mappings.db`**: 存真实→占位符映射，需文件权限保护
- **展示层**: 还原后显示真实信息
- **LLM 侧**: 只看到占位符

## 项目结构

```
deepseek-agents/
├── config.yaml              # 规则配置
├── pyproject.toml
├── src/sensitive_guard/
│   ├── config.py            # 配置加载
│   ├── detector.py          # 敏感信息检测
│   ├── mapping.py           # 占位符映射（SQLite 持久化）
│   ├── llm_client.py        # LLM HTTP 客户端（拦截过滤+还原）
│   ├── agent_correct.py     # Agent 自修正
│   └── cli.py               # CLI 入口
└── test_verify.py           # 验证脚本
```
