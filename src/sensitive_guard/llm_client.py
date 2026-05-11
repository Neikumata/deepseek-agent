"""
LLM HTTP 底层

负责从原始 HTTP 请求层做拦截过滤：
1. 发包前对请求体（messages）做检测 + 替换
2. 收到响应后对 content 做还原
"""

from __future__ import annotations

SYSTEM_PROMPT_PREFIX = """\
你是一个智能助手。用户消息中出现的 `__PH_SENSITIVE_N__` 格式文本是系统内部标识符，
代表隐私信息的安全映射值。你必须：
1. 将它当作真实内容来处理，不要在回复中讨论它是否是占位符或脱敏文本
2. 如果它是一个手机号/账号/密钥等，就当成真正的手机号/账号/密钥来回答问题
3. 绝对不要回复"占位符""脱敏""隐私保护"等与系统处理相关的任何内容
"""

import json
from dataclasses import dataclass
from typing import Any

import httpx

from .config import AgentConfig, GuardConfig
from .detector import SensitiveDetector
from .mapping import MappingStore


class GuardedLLMClient:
    """
    LLM HTTP 客户端，在请求/响应两端做敏感信息过滤与还原。
    """

    def __init__(self, guard_config: GuardConfig):
        self.guard_config = guard_config
        self.agent_config = guard_config.agent
        self.detector = SensitiveDetector(
            rules=guard_config.rules,
            sensitive_words=guard_config.sensitive_words,
        )
        self.mapping = MappingStore(behavior=guard_config.behavior)
        self._http = httpx.Client(
            base_url=self.agent_config.api_base_url,
            headers={
                "Authorization": f"Bearer {self.agent_config.api_key}",
                "Content-Type": "application/json",
            },
            timeout=60.0,
        )

    def chat(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        **kwargs,
    ) -> GuardedResponse:
        """
        发送聊天请求，自动过滤敏感信息并还原响应。

        Args:
            messages: OpenAI 格式的消息列表
            model: 模型名称
            **kwargs: 其他 OpenAI API 参数

        Returns:
            GuardedResponse 包含原始响应和过滤还原后的内容
        """
        # 0. 在 messages 最前面注入 system prompt（如果用户没有自定义 system prompt）
        if not any(m.get("role") == "system" for m in messages):
            messages = [{"role": "system", "content": SYSTEM_PROMPT_PREFIX}] + list(messages)
        else:
            first_system = next(m for m in messages if m["role"] == "system")
            first_system["content"] = SYSTEM_PROMPT_PREFIX + "\n" + first_system["content"]

        # 1. 拆解 messages 文本
        texts = _extract_texts(messages)
        combined = "\n".join(texts)

        # 2. 检测
        detection_result = self.detector.detect(combined)

        # 3. 替换
        sanitized_messages = _replace_messages_text(
            messages, self.mapping, self.detector
        )

        # 4. 发送请求
        payload = {
            "model": model or self.agent_config.model,
            "messages": sanitized_messages,
            **kwargs,
        }

        response = self._http.post("/v1/chat/completions", json=payload)
        response.raise_for_status()
        raw_body = response.json()

        # 5. 还原响应中的占位符
        restored_body = _restore_response(raw_body, self.mapping)

        return GuardedResponse(
            raw=raw_body,
            sanitized=restored_body,
            detection=detection_result,
            mapping_stats=self.mapping.stats(),
        )

    def close(self):
        """关闭 HTTP 客户端"""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


@dataclass
class GuardedResponse:
    """过滤后的 LLM 响应"""
    raw: dict[str, Any]
    sanitized: dict[str, Any]
    detection: Any  # DetectionResult
    mapping_stats: dict[str, Any]

    @property
    def content(self) -> str:
        """还原后的消息内容"""
        choices = self.sanitized.get("choices", [])
        if not choices:
            return ""
        return choices[0].get("message", {}).get("content", "")

    @property
    def raw_content(self) -> str:
        """原始消息内容（占位符未还原）"""
        choices = self.raw.get("choices", [])
        if not choices:
            return ""
        return choices[0].get("message", {}).get("content", "")


def _extract_texts(messages: list[dict[str, str]]) -> list[str]:
    """从消息列表中提取所有文本内容"""
    texts = []
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            # 多模态 content 格式
            for part in content:
                if isinstance(part, dict) and "text" in part:
                    texts.append(part["text"])
    return texts


def _replace_messages_text(
    messages: list[dict[str, str]],
    mapping: MappingStore,
    detector: SensitiveDetector,
) -> list[dict[str, Any]]:
    """对 messages 中的每条 content 做检测 + 替换"""
    result = []
    for msg in messages:
        new_msg = dict(msg)
        content = msg.get("content", "")
        if isinstance(content, str):
            detection = detector.detect(content)
            new_msg["content"] = mapping.replace_all(content, detection.matches)
        elif isinstance(content, list):
            new_parts = []
            for part in content:
                if isinstance(part, dict) and "text" in part:
                    detection = detector.detect(part["text"])
                    new_part = dict(part)
                    new_part["text"] = mapping.replace_all(part["text"], detection.matches)
                    new_parts.append(new_part)
                else:
                    new_parts.append(part)
            new_msg["content"] = new_parts
        else:
            detection = detector.detect(str(content))
            new_msg["content"] = mapping.replace_all(str(content), detection.matches)
        result.append(new_msg)
    return result


def _restore_response(raw_body: dict, mapping: MappingStore) -> dict:
    """递归还原 JSON 响应中的占位符"""
    import copy
    body = copy.deepcopy(raw_body)
    return _restore_recursive(body, mapping)


def _restore_recursive(obj: Any, mapping: MappingStore) -> Any:
    """递归遍历 JSON 结构，还原占位符"""
    if isinstance(obj, str):
        return mapping.restore(obj)
    elif isinstance(obj, dict):
        return {k: _restore_recursive(v, mapping) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_restore_recursive(item, mapping) for item in obj]
    return obj