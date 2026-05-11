"""
Agent 自修正模块

当检测器漏掉某些敏感信息时，调用 LLM 分析文本，
生成新的检测规则或更新现有规则配置。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .config import AgentConfig, GuardConfig, SensitiveRule


@dataclass
class AgentSuggestion:
    """Agent 给出的规则修正建议"""
    action: str  # "add" | "modify" | "disable"
    rule_name: str
    pattern: str
    description: str
    confidence: float
    reason: str


RULE_ANALYSIS_SYSTEM_PROMPT = """你是一个安全规则分析助手。你的任务是分析用户提供的文本，
找出其中所有可能存在的敏感信息（包括那些即便已有规则覆盖的），
并为每种敏感信息类型提供正则表达式检测规则。

重要：正则表达式需要匹配 key=value 或 key: value 格式的完整键值对。
例如 "alipay_account=test@123" 应该用 `alipay[^=]*\\s*=\\s*\\S+` 匹配，
而不是 `alipay\\s*[:=]`（后者要求 alipay 后紧跟 = 或 :）。

请以 JSON 数组格式返回结果，每个元素包含：
- action: "add"（新增）或 "modify"（修改已有规则）
- rule_name: 规则名称（英文，snake_case）
- pattern: 正则表达式（用于匹配该类型敏感信息）
- description: 规则描述（中文）
- confidence: 置信度（0-1 之间的浮点数）
- reason: 为什么需要这条规则（中文）

只返回 JSON，不要包含其他内容。

示例输出格式：
[
  {
    "action": "add",
    "rule_name": "alipay_account",
    "pattern": "(?i)alipay[^=]*\\\\s*=\\\\s*\\\\S+",
    "description": "支付宝账号检测",
    "confidence": 0.85,
    "reason": "文本中出现了支付宝账号"
  }
]"""


class RuleAgent:
    """规则自修正 Agent"""

    def __init__(self, agent_config: AgentConfig):
        self.config = agent_config
        self._http = None

    def _get_http(self):
        """惰性创建 HTTP 客户端"""
        if self._http is None:
            import httpx
            self._http = httpx.Client(
                base_url=self.config.api_base_url,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=60.0,
            )
        return self._http

    def analyze(
        self,
        text: str,
        existing_rules: list[SensitiveRule],
        detected_sensitive_count: int,
    ) -> list[AgentSuggestion]:
        """
        分析文本中所有可能的敏感信息，包括已有规则未覆盖的类型。

        Args:
            text: 需要分析的文本
            existing_rules: 当前已有的检测规则
            detected_sensitive_count: 当前检测器已命中的数量

        Returns:
            规则修正建议列表
        """
        # 构建已知规则描述
        rules_desc = "\n".join(
            f"- {r.name}: {r.description} (pattern: {r.pattern}, enabled={r.enabled})"
            for r in existing_rules
        )

        user_prompt = f"""已知检测规则：
{rules_desc}

当前检测器已命中 {detected_sensitive_count} 处。

请分析以下文本，找出其中所有可能存在的敏感信息类型（包括已有规则覆盖的和未覆盖的）。
对于已有规则已覆盖的，如果规则可改进则返回 modify；对于新类型则返回 add。

{text[:4000]}"""

        messages = [
            {"role": "system", "content": RULE_ANALYSIS_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        http = self._get_http()
        response = http.post("/v1/chat/completions", json={
            "model": self.config.model,
            "messages": messages,
            "temperature": 0.1,
        })
        response.raise_for_status()
        body = response.json()

        content = body["choices"][0]["message"]["content"]

        # 解析 JSON 响应
        suggestions = _parse_agent_response(content)
        return suggestions

    def _normalize_pattern(self, pattern: str) -> str:
        """标准化正则表达式以进行字符串比较"""
        import re as _re
        p = pattern
        # 去除不必要的单字符类: [\d] -> \d, [\w] -> \w, [\s] -> \s
        p = _re.sub(r'\[(\\(?:d|w|s|D|W|S))\]', r'\1', p)
        # 统一空白
        p = p.strip()
        return p

    def apply_suggestions(
        self,
        suggestions: list[AgentSuggestion],
        current_rules: list[SensitiveRule],
        confidence_threshold: float = 0.7,
    ) -> list[SensitiveRule]:
        """
        应用 Agent 的建议，返回更新后的规则列表。

        Args:
            suggestions: Agent 的建议列表
            current_rules: 当前规则列表
            confidence_threshold: 置信度阈值（低于此值的建议被忽略）

        Returns:
            更新后的规则列表
        """
        rules_dict = {r.name: r for r in current_rules}

        for sug in suggestions:
            if sug.confidence < confidence_threshold:
                continue

            # 去重：normalize 后对比 pattern，相同则跳过
            if sug.rule_name in rules_dict:
                existing = rules_dict[sug.rule_name]
                if (self._normalize_pattern(existing.pattern) == self._normalize_pattern(sug.pattern)):
                    existing.enabled = True
                    continue

            if sug.action == "add":
                if sug.rule_name not in rules_dict:
                    rules_dict[sug.rule_name] = SensitiveRule(
                        name=sug.rule_name,
                        description=sug.description,
                        pattern=sug.pattern,
                        enabled=True,
                    )

            elif sug.action == "modify":
                if sug.rule_name in rules_dict:
                    rules_dict[sug.rule_name] = SensitiveRule(
                        name=sug.rule_name,
                        description=sug.description,
                        pattern=sug.pattern,
                        enabled=True,
                    )

            elif sug.action == "disable":
                if sug.rule_name in rules_dict:
                    rules_dict[sug.rule_name].enabled = False

        return list(rules_dict.values())

    def close(self):
        if self._http:
            self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _parse_agent_response(content: str) -> list[AgentSuggestion]:
    """解析 Agent 返回的 JSON 响应"""
    # 尝试从 markdown 代码块中提取 JSON
    json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', content)
    if json_match:
        content = json_match.group(1)

    # 尝试提取 JSON 数组
    array_match = re.search(r'\[[\s\S]*\]', content)
    if array_match:
        content = array_match.group(0)

    try:
        items = json.loads(content)
    except json.JSONDecodeError:
        return []

    suggestions = []
    for item in items:
        suggestions.append(AgentSuggestion(
            action=item.get("action", "add"),
            rule_name=item.get("rule_name", ""),
            pattern=item.get("pattern", ""),
            description=item.get("description", ""),
            confidence=float(item.get("confidence", 0.5)),
            reason=item.get("reason", ""),
        ))

    return suggestions


def auto_correct(
    text: str,
    config: GuardConfig,
    detector_result,
) -> tuple[list[SensitiveRule], list[AgentSuggestion]]:
    """
    自动修正流程：
    1. 调用 Agent 分析文本
    2. 应用建议更新规则

    Returns:
        (更新后的规则列表, Agent 建议列表)
    """
    agent = RuleAgent(agent_config=config.agent)
    suggestions = agent.analyze(
        text=text,
        existing_rules=config.rules,
        detected_sensitive_count=detector_result.total_count,
    )
    updated_rules = agent.apply_suggestions(
        suggestions=suggestions,
        current_rules=config.rules,
        confidence_threshold=config.agent.confidence_threshold,
    )
    agent.close()
    return updated_rules, suggestions