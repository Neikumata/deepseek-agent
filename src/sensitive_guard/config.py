"""
规则配置模块

负责加载、解析 config.yaml，提供规则对象的读取接口。
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class SensitiveRule:
    """单条敏感信息检测规则"""
    name: str
    description: str
    pattern: str
    enabled: bool = True


@dataclass
class BehaviorConfig:
    """替换行为配置"""
    replacement_strategy: str = "placeholder"
    placeholder_prefix: str = "__PH_SENSITIVE_"
    mask_char: str = "*"
    mapping_db_path: str = "~/.sensitive_guard/mappings.db"


@dataclass
class AgentConfig:
    """Agent 自修正配置"""
    llm_provider: str = "openai"
    api_base_url: str = "https://api.deepseek.com"
    api_key: str = ""
    model: str = "deepseek-chat"
    confidence_threshold: float = 0.95
    max_retries: int = 3


@dataclass
class GuardConfig:
    """完整的过滤配置"""
    rules: list[SensitiveRule] = field(default_factory=list)
    sensitive_words: list[str] = field(default_factory=list)
    behavior: BehaviorConfig = field(default_factory=BehaviorConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)


def load_config(path: str | Path = "config.yaml") -> GuardConfig:
    """
    从 YAML 文件加载配置。

    Args:
        path: 配置文件路径，默认当前目录下的 config.yaml

    Returns:
        GuardConfig 实例
    """
    path = Path(path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"配置文件不存在: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raise ValueError("配置文件为空")

    # 解析规则
    rules = []
    for r in raw.get("rules", []):
        rules.append(SensitiveRule(
            name=r["name"],
            description=r.get("description", ""),
            pattern=r["pattern"],
            enabled=r.get("enabled", True),
        ))

    # 解析行为配置
    behavior_raw = raw.get("behavior", {})
    behavior = BehaviorConfig(
        replacement_strategy=behavior_raw.get("replacement_strategy", "placeholder"),
        placeholder_prefix=behavior_raw.get("placeholder_prefix", "__PH_SENSITIVE_"),
        mask_char=behavior_raw.get("mask_char", "*"),
        mapping_db_path=behavior_raw.get("mapping_db_path", "~/.sensitive_guard/mappings.db"),
    )

    # 解析 agent 配置
    agent_raw = raw.get("agent", {})
    agent = AgentConfig(
        llm_provider=agent_raw.get("llm_provider", "openai"),
        api_base_url=agent_raw.get("api_base_url", "https://api.deepseek.com"),
        api_key=_resolve_env(agent_raw.get("api_key", "")),
        model=agent_raw.get("model", "deepseek-chat"),
        confidence_threshold=agent_raw.get("confidence_threshold", 0.95),
        max_retries=agent_raw.get("max_retries", 3),
    )

    return GuardConfig(
        rules=rules,
        sensitive_words=raw.get("sensitive_words", []),
        behavior=behavior,
        agent=agent,
    )


def _resolve_env(value: str) -> str:
    """解析 ${ENV_VAR} 格式的环境变量占位符"""
    import re
    if re.match(r'^\$\{[A-Za-z_][A-Za-z0-9_]*\}$', value):
        var_name = value[2:-1]
        import os
        return os.environ.get(var_name, "")
    return value
