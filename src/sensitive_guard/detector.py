"""
检测模块

根据规则配置对输入文本或结构化内容做敏感信息检测。
"""

import re
from dataclasses import dataclass, field

from .config import SensitiveRule


@dataclass
class DetectionMatch:
    """单次检测匹配结果"""
    rule_name: str
    matched_text: str
    start: int
    end: int


@dataclass
class DetectionResult:
    """检测结果"""
    has_sensitive: bool
    matches: list[DetectionMatch] = field(default_factory=list)
    total_count: int = 0

    @property
    def rule_names(self) -> set[str]:
        """涉及到的规则名称集合"""
        return {m.rule_name for m in self.matches}


class SensitiveDetector:
    """敏感信息检测器"""

    def __init__(self, rules: list[SensitiveRule], sensitive_words: list[str] | None = None):
        """
        Args:
            rules: 规则列表
            sensitive_words: 敏感词列表（精确匹配）
        """
        self.rules = [r for r in rules if r.enabled]
        self.sensitive_words = set(sensitive_words or [])
        self._compiled: list[tuple[SensitiveRule, re.Pattern]] = []

    def _ensure_compiled(self):
        """惰性编译正则表达式"""
        if self._compiled:
            return
        for rule in self.rules:
            try:
                compiled = re.compile(rule.pattern)
                self._compiled.append((rule, compiled))
            except re.error as e:
                import sys
                print(f"[warn] 规则 '{rule.name}' 正则编译失败: {e}", file=sys.stderr)

    def detect(self, text: str) -> DetectionResult:
        """
        对文本执行敏感信息检测。

        Args:
            text: 待检测文本

        Returns:
            DetectionResult 包含所有匹配结果
        """
        self._ensure_compiled()
        matches: list[DetectionMatch] = []

        # 正则规则匹配
        for rule, compiled in self._compiled:
            for m in compiled.finditer(text):
                matches.append(DetectionMatch(
                    rule_name=rule.name,
                    matched_text=m.group(0),
                    start=m.start(),
                    end=m.end(),
                ))

        # 敏感词精确匹配
        if self.sensitive_words:
            for word in self.sensitive_words:
                start = 0
                while True:
                    idx = text.find(word, start)
                    if idx == -1:
                        break
                    matches.append(DetectionMatch(
                        rule_name="sensitive_word",
                        matched_text=word,
                        start=idx,
                        end=idx + len(word),
                    ))
                    start = idx + 1

        # 按位置排序，去重
        matches.sort(key=lambda m: (m.start, -m.end))
        deduped = _deduplicate_matches(matches)

        return DetectionResult(
            has_sensitive=len(deduped) > 0,
            matches=deduped,
            total_count=len(deduped),
        )

    def detect_structured(self, content: dict | list | str) -> DetectionResult:
        """
        对结构化内容（dict/list/str）做递归检测。
        将所有叶子节点的文本拼接后检测。
        """
        text = _flatten_content(content)
        return self.detect(text)

    def test_detection(self, text: str) -> float:
        """
        测试检测覆盖率：用 LLM 标注的敏感信息作为 ground truth 比对。
        返回检测召回率。目前为占位，后续对接 agent 时实现。
        """
        result = self.detect(text)
        # TODO: 真正的 recall 计算需要 ground truth 标注
        return 1.0 if result.total_count > 0 else 0.0


def _deduplicate_matches(matches: list[DetectionMatch]) -> list[DetectionMatch]:
    """去重重叠的匹配（保留范围最大的）"""
    if not matches:
        return []

    result: list[DetectionMatch] = []
    for m in matches:
        # 检查是否与已保留的匹配重叠
        overlapping = False
        for kept in result:
            if not (m.end <= kept.start or m.start >= kept.end):
                # 重叠：保留范围更大的
                if (m.end - m.start) > (kept.end - kept.start):
                    result.remove(kept)
                else:
                    overlapping = True
                    break
        if not overlapping:
            result.append(m)
    return result


def _flatten_content(obj: dict | list | str) -> str:
    """将结构化内容递归拼成字符串"""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten_content(v) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(_flatten_content(item) for item in obj)
    return str(obj)
