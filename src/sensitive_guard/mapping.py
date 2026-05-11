"""
替换映射模块

管理敏感信息 → 占位符 的双向映射，持久化到 SQLite。
"""

import itertools
import os
from pathlib import Path

from .config import BehaviorConfig


class MappingStore:
    """
    双向映射存储。
    
    持久化到 SQLite（通过 sqlitedict），支持：
    - 真实值 → 占位符
    - 占位符 → 真实值 的逆向查询
    """

    def __init__(self, behavior: BehaviorConfig):
        self.behavior = behavior
        self._db_path = Path(behavior.mapping_db_path).expanduser().resolve()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._real_to_placeholder: dict[str, str] = {}
        self._placeholder_to_real: dict[str, str] = {}
        self._counter: itertools.count | None = None
        self._loaded = False

    def _ensure_loaded(self):
        """惰性加载已持久化的映射"""
        if self._loaded:
            return
        self._loaded = True

        try:
            from sqlitedict import SqliteDict
            with SqliteDict(str(self._db_path), autocommit=True) as db:
                self._real_to_placeholder = dict(db.items())
            self._placeholder_to_real = {v: k for k, v in self._real_to_placeholder.items()}
            # 从已有映射中恢复最大 ID
            max_id = 0
            for ph in self._real_to_placeholder.values():
                try:
                    # 占位符格式: __PH_SENSITIVE_{id}__
                    id_part = ph.replace(self.behavior.placeholder_prefix, "").strip("_")
                    max_id = max(max_id, int(id_part))
                except (ValueError, IndexError):
                    pass
            self._counter = itertools.count(max_id + 1)
        except Exception:
            self._counter = itertools.count(1)

    def get_placeholder(self, real_value: str) -> str:
        """
        获取或创建真实值对应的占位符。

        如果该值已有映射则复用，否则创建新占位符。
        """
        self._ensure_loaded()

        if real_value in self._real_to_placeholder:
            return self._real_to_placeholder[real_value]

        # 创建新占位符
        ph_id = next(self._counter)  # type: ignore[arg-type]
        placeholder = f"{self.behavior.placeholder_prefix}{ph_id}__"

        self._real_to_placeholder[real_value] = placeholder
        self._placeholder_to_real[placeholder] = real_value

        self._persist_add(real_value, placeholder)
        return placeholder

    def get_real(self, placeholder: str) -> str | None:
        """从占位符还原真实值"""
        self._ensure_loaded()
        return self._placeholder_to_real.get(placeholder)

    def replace_all(self, text: str, matches: list) -> str:
        """
        对文本中所有检测到的敏感信息执行占位符替换。

        Args:
            text: 原始文本
            matches: DetectionMatch 列表（已按位置排序）

        Returns:
            替换后的文本
        """
        if not matches:
            return text

        # 从后往前替换，避免位置偏移
        result = text
        for m in sorted(matches, key=lambda x: x.start, reverse=True):
            placeholder = self.get_placeholder(m.matched_text)
            result = result[:m.start] + placeholder + result[m.end:]
        return result

    def restore(self, text: str) -> str:
        """
        将文本中的占位符还原为真实值。
        """
        self._ensure_loaded()
        for placeholder, real_value in self._placeholder_to_real.items():
            text = text.replace(placeholder, real_value)
        return text

    def _persist_add(self, real_value: str, placeholder: str):
        """写入 SQLite"""
        try:
            from sqlitedict import SqliteDict
            with SqliteDict(str(self._db_path), autocommit=True) as db:
                db[real_value] = placeholder
        except Exception:
            pass  # 持久化失败不影响内存映射

    def stats(self) -> dict:
        """返回映射统计信息"""
        self._ensure_loaded()
        return {
            "total_mappings": len(self._real_to_placeholder),
            "db_path": str(self._db_path),
        }
